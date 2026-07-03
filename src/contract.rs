use crate::names::{Id, Secret, Name, secp256k1::SecretKey, now};

use crate::channel::{Inbox, InboxHandler, Sink, Stream, Channel, Event};
use crate::cache::Cache;
use crate::Air;

use std::collections::{HashSet, BTreeMap, VecDeque, btree_map::Entry};
use std::hash::Hash;
use std::any::TypeId;
use std::sync::Arc;
use std::any::Any;
use std::fmt::Debug;

use serde::{Serialize, Deserialize};

use tokio::task::JoinSet;

use crate::ams::{Ams, Ref};

pub trait Contract: Serialize + for<'a> Deserialize<'a> + Send + Sync + Clone + Debug + 'static {
    type Init: Serialize + for<'a> Deserialize<'a> + Hash + Clone + Send + Sync;
    fn init(init: Self::Init, metadata: Metadata) -> Self;

    fn id() -> Id;

    fn reactants() -> Reactants<Self>;
}

pub trait Reactant<C: Contract>: Serialize + for<'a> Deserialize<'a> + Debug + Clone + Send + Sync + 'static {
    type Output: Clone + Clone + Send + Sync + 'static;

    fn id() -> Id;

    fn apply(self, model: &mut C, metadata: Metadata) -> Self::Output;
}

type GetReactant<C> = Box<dyn Fn(Vec<u8>, &mut C, Metadata) -> Option<AnyOutput<C>> + Send + Sync>;
pub struct Reactants<C: Contract>(BTreeMap<Id, (TypeId, String, GetReactant<C>)>);
impl<C: Contract> std::fmt::Debug for Reactants<C> {fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.debug_map().entries(self.0.iter().map(|(id, i)| (id, &i.1))).finish()
}}
impl<C: Contract> Default for Reactants<C> {fn default() -> Self {Reactants(BTreeMap::default())}}
impl<C: Contract> Reactants<C> {
    pub fn add<R: Reactant<C>>(mut self) -> Self {
        self.0.insert(R::id(), (TypeId::of::<R>(), std::any::type_name::<R>().to_string(), Box::new(move |bytes: Vec<u8>, contract: &mut C, metadata: Metadata|
            match postcard::from_bytes::<R>(&bytes) {
                Ok(reactant) => Some(AnyOutput::new::<R>(reactant.apply(contract, metadata))),
                Err(e) => {println!("Deserialize Reactant: {e:?}"); None}
            }
        )));
        self
    } 

    fn id<R: Reactant<C> + 'static>(&self) -> Option<Id> {
        self.0.iter().find_map(|(id, (ty, _, _))| (*ty == TypeId::of::<R>()).then_some(*id))
    }

    fn apply(&self, id: &Id, reactant: Vec<u8>, contract: &mut C, metadata: Metadata) -> Option<AnyOutput<C>> {
        match self.0.get(id) {
            Some((_, _, apply)) => (apply)(reactant, contract, metadata),
            None if *id == C::id() => {println!("Tried to Init Contract Again"); None}
            None => {println!("Unknown Reactant {:?}", id); None}
        }
    }
}

#[derive(Clone)]
pub struct AnyInstance(Arc<Box<dyn Fn() -> Box<dyn Any + Send + Sync> + Send + Sync>>, Location);
impl Debug for AnyInstance {fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {f.debug_tuple("AnyInstance").field(&self.1).finish()}}
impl AnyInstance {
    pub fn new<C: Contract>(instance: Instance<C>) -> Self {
        let location = instance.location;
        AnyInstance(Arc::new(Box::new(move || Box::new(instance.clone()))), location)
    }
    pub fn downcast<C: Contract>(&self) -> Option<Instance<C>> {
        (self.0)().downcast::<Instance<C>>().ok().map(|i| *i)
    }
}

#[derive(Clone)]
pub struct AnyOutput<C: Contract>(Arc<Box<dyn Fn() -> Box<dyn Any + Send + Sync> + Send + Sync>>, std::marker::PhantomData<C>);
impl<C: Contract> Debug for AnyOutput<C> {fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {f.debug_struct("AnyOutput").finish()}}

impl<C: Contract> AnyOutput<C> {
    pub fn new<R: Reactant<C>>(output: R::Output) -> Self {
        AnyOutput(Arc::new(Box::new(move || Box::new(output.clone()))), std::marker::PhantomData::<C>)
    }
    pub fn downcast<R: Reactant<C>>(&self) -> Option<R::Output> {
        (self.0)().downcast::<R::Output>().ok().map(|o| *o)
    }
}

pub enum PendingResult<C: Contract, O: Clone + Send + Sync + 'static, E: Clone + Send + Sync + 'static, R: Reactant<C, Output = Result<O, E>>> {
    Ok(Pending<C, R>),
    Err(E)
}
impl<C: Contract, O: Clone + Send + Sync + 'static, E: Clone + Send + Sync + 'static, R: Reactant<C, Output = Result<O, E>>> PendingResult<C, O, E, R> {
    pub async fn confirmed(self) -> Result<O, E> {match self {
        Self::Ok(pending) => pending.confirmed().await.clone(),
        Self::Err(e) => Err(e)
    }}
}

#[derive(Clone, Debug, PartialEq)]
pub struct Pending<C: Contract, R: Reactant<C>>(Ams<(R::Output, bool), bool>);
impl<C: Contract, R: Reactant<C>> Pending<C, R> {
    fn new(output: R::Output) -> Self {Pending(Ams::new((output, false)))}

    pub fn is_confirmed(&self) -> bool {self.0.load().1}
    pub fn load(&self) -> Ref<R::Output> {self.0.load_partial(|r| &r.0)}
    pub fn get_update(&mut self) -> Option<bool> {self.0.get_update()}
    pub async fn confirmed(mut self) -> Ref<R::Output> {
        loop {if self.0.listen().await {break self.load()}}
    }

    fn update(&self, output: R::Output, confirmed: bool) {
        let mut lock = self.0.lock();
        *lock = (output, confirmed);
        lock.commit(confirmed);
    }
}

type GetOutput<C> = Box<dyn Fn(&mut C, Metadata) -> AnyOutput<C> + Send + Sync>;

#[derive(Clone)]
pub struct PendingReactant<C: Contract>(Id, Arc<GetOutput<C>>);
impl<C: Contract> Debug for PendingReactant<C> {fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.debug_tuple("PendingReactant").field(&self.0).finish()
}}
impl<C: Contract> PendingReactant<C> {
    pub fn new<R: Reactant<C>>(id: Id, reactant: R, pending: Pending<C, R>) -> Self {
        PendingReactant(id, Arc::new(Box::new(move |contract: &mut C, metadata: Metadata| {
            let output = reactant.clone().apply(contract, metadata);
            pending.update(output.clone(), metadata.confirmed);
            AnyOutput::new::<R>(output)
        })))
    }
    pub fn apply(&mut self, contract: &mut C, metadata: Metadata) -> AnyOutput<C> {
        (self.1)(contract, metadata)
    }
}

#[derive(Clone)]
pub struct Instance<C: Contract>{
    id: Id,
    air: Air,
    sink: Sink,
    location: Location,
    reactants: Arc<Reactants<C>>,
    confirmed: Ams<Option<C>, AnyOutput<C>>,
    pending: Ams<(VecDeque<PendingReactant<C>>, Option<C>), ()>,
    head: Ams<bool, bool>
}

impl<C: Contract> std::fmt::Debug for Instance<C> {fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.debug_struct("Instance").field("id", &self.id).field("confirmed", &self.confirmed).field("pending", &self.pending).finish()
}}

impl<C: Contract> Instance<C> {
    pub fn id(&self) -> Id {self.id}

    fn start(air: Air, location: Location, init: Option<C::Init>) -> Self {
        let id = Id::hash(&location);
        let cache = Cache::new(format!("{}/{}/{}", air.name, C::id(), id)).unwrap();
        let secret = air.secret.derive(&[C::id(), id]);
        let (channel, contract) = cache.get::<(Channel, Option<C>)>("instance").unwrap().unwrap_or((Channel::new(location.key), None));
        let (stream, sink) = channel.start(air.clone(), secret);
        if let Some(init) = init.as_ref() && contract.is_none() {
            sink.write_sync(postcard::to_allocvec(&(id, postcard::to_allocvec(init).unwrap())).unwrap());
        }
        let contract = contract.or(init.map(|i| C::init(i, Metadata::pending(air.name))));
        let reactants = Arc::new(C::reactants());
        let confirmed = Ams::new(contract.clone());
        let pending = Ams::new((VecDeque::new(), contract));
        let head = Ams::new(false);
        let instance = Instance{sink, air: air.clone(), id, location, reactants, confirmed, pending, head};
        air.handle.spawn(instance.clone().run(cache, stream));
        instance
    }

    pub fn share(&self, name: Name) {
        InboxHandler::send(self.air.clone(), name, postcard::to_allocvec(&self.location).unwrap());
    }

  //pub fn clear_confirmed(&mut self) { self.confirmed.clear_updates(); }
  //pub fn clear_pending(&mut self) { self.pending.clear_updates(); }
  //pub fn clear_updates(&mut self) { self.clear_confirmed(); self.clear_pending(); }

    pub fn confirmed_update(&mut self) -> Option<AnyOutput<C>> {
        self.confirmed.get_update()
    }

    pub async fn listen_confirmed(&mut self) -> AnyOutput<C> {
        self.confirmed.listen().await
    }

    pub fn confirmed(&self) -> Ref<C> {
        self.confirmed.load_partial(|c| c.as_ref().unwrap())
    }

    pub fn pending_updated(&mut self) -> bool {
        let r = self.pending.get_update().is_some();
        self.pending.clear_updates();
        r
    }

    pub async fn listen_pending(&mut self) {
        self.pending.listen().await
    }

    pub fn pending(&self) -> Ref<C> {
        self.pending.load_partial(|i| i.1.as_ref().unwrap())
    }


    ///If the outer result is Err the reactant has not been sent and will not update its state in the future
    pub fn try_apply<O: Send + Sync + Clone + Debug, E: Sync + Send + Clone + Debug, R: Reactant<C, Output = Result<O, E>>>(&mut self, reactant: R) -> PendingResult<C, O, E, R> {
        let id = self.reactants.id::<R>().expect("Reactant is not listed in Contract::reactants()");
        let mut pending = self.pending.lock();
        let metadata = Metadata::pending(self.air.name);
        match reactant.clone().apply(pending.1.as_mut().unwrap(), metadata) {
            Err(e) => PendingResult::Err(e),
            Ok(output) => {
                let output = Pending::new(Ok(output));
                let id = self.sink.write_sync(postcard::to_allocvec(&(id, postcard::to_allocvec(&reactant).unwrap())).unwrap());
                let reactant = PendingReactant::new(id, reactant, output.clone());
                pending.0.push_back(reactant);
                pending.commit(());
                PendingResult::Ok(output)
            }
        }
    }

    pub fn apply<R: Reactant<C>>(&mut self, reactant: R) -> Pending<C, R> {
        let id = self.reactants.id::<R>().expect("Reactant is not listed in Contract::reactants()");
        let mut pending = self.pending.lock();
        let metadata = Metadata::pending(self.air.name);
        let output = Pending::new(reactant.clone().apply(pending.1.as_mut().unwrap(), metadata));
        let id = self.sink.write_sync(postcard::to_allocvec(&(id, postcard::to_allocvec(&reactant).unwrap())).unwrap());
        let reactant = PendingReactant::new(id, reactant, output.clone());
        pending.0.push_back(reactant);
        pending.commit(());
        output
    }

    async fn run(self, mut cache: Cache, mut stream: Stream) {
        loop {
            let (timestamp, event) = stream.read().await;
            match event {
                Event::Head => {
                    let mut lock = self.head.lock();
                    *lock = true;
                    lock.commit(true);
                },
                Event::Data(signer, data, rid) => {
                    if let Ok((id, bytes)) = postcard::from_bytes::<(Id, Vec<u8>)>(&data) {
                        let metadata = Metadata::confirmed(signer, timestamp);
                        if self.confirmed.load().is_none() {
                            if id == self.id && let Ok(init) = postcard::from_bytes(&bytes) {
                                self.confirmed.store(Some(C::init(init, metadata)));
                            } else {
                                println!("Invalid Contract Init");
                            }
                        } else {
                            let mut pending = self.pending.lock();
                            let mut confirmed = self.confirmed.lock();
                            let queue = &mut pending.0;

                            let output = if let Some(rid) = rid && queue.front().map(|pending| pending.0 == rid).unwrap_or_default() {
                                Some(queue.pop_front().unwrap().apply(confirmed.as_mut().unwrap(), metadata))
                            } else {
                                self.reactants.apply(&id, bytes, confirmed.as_mut().unwrap(), metadata)
                            };

                            if let Some(output) = output {
                                pending.1 = confirmed.clone();
                                let (queue, sub) = &mut *pending;
                                for pending in &mut *queue {
                                    pending.apply(sub.as_mut().unwrap(), Metadata::pending(self.air.name));
                                }
                                if queue.is_empty() {pending.commit_silent();} else {pending.commit(());}
                                confirmed.commit(output);
                            }
                        }
                    }
                },
                Event::Garbage => {}
            }
            cache.insert("instance", &(&stream.channel(), &*self.confirmed.load())).unwrap();
        }
    }

    pub fn is_near_head(&self) -> bool {*self.head.load()}
    pub async fn head(&mut self) {
        loop { if *self.head.load() {break;} self.head.listen().await;}
    }
}

type Builder = Arc<Box<dyn Fn(Location) -> AnyInstance + Send + Sync>>;

#[derive(Clone)]
pub struct Instances(Ams<BTreeMap<Id, BTreeMap<Id, AnyInstance>>, AnyInstance>, Ams<BTreeMap<Id, Builder>, Id>, Air);
impl Instances {
    pub fn register<C: Contract>(&self) {
        let c_id = C::id();
        let air = self.2.clone();
        if !self.1.load().contains_key(&c_id) {
            let mut builders = self.1.lock();
            if let Entry::Vacant(vac) = builders.entry(c_id) {
                vac.insert(Arc::new(Box::new(move |location: Location| AnyInstance::new(Instance::<C>::start(air.clone(), location, None)))));
                builders.commit(c_id);
            }
        }
    }

    pub fn create<C: Contract>(&self, init: C::Init) -> Instance<C> {
        self.register::<C>();
        let c_id = C::id();
        let location = Location::new::<C>(&self.2.secret, &init);
        let id = Id::hash(&location);
        match self.0.load().get(&c_id).and_then(|i| i.get(&id)) {
            Some(instance) => instance.downcast().unwrap(),
            None => {
                let mut instances = self.0.lock();
                match instances.entry(c_id).or_default().entry(id) {
                    Entry::Occupied(occ) => occ.get().downcast().unwrap(),
                    Entry::Vacant(vac) => {
                        let instance = Instance::<C>::start(self.2.clone(), location, Some(init));
                        let any = AnyInstance::new(instance.clone());
                        vac.insert(any.clone());
                        instances.commit(any);
                        instance
                    }
                }
            }
        }
    }

    fn build(&self, location: Location) -> Option<AnyInstance> {
        let id = Id::hash(&location);
        match self.0.load().get(&location.contract_id)?.get(&id) {
            Some(instance) => Some(instance.clone()),
            None => {
                let mut instances = self.0.lock();
                match instances.get_mut(&location.contract_id)?.entry(id) {
                    Entry::Occupied(occ) => Some(occ.get().clone()),
                    Entry::Vacant(vac) => {
                        let instance = (self.1.load().get(&location.contract_id).unwrap())(location);
                        vac.insert(instance.clone());
                        instances.commit(instance.clone());
                        Some(instance) 
                    }
                }
            }
        }
    }

    pub fn list<C: Contract>(&self) -> Vec<Instance<C>> {
        match self.0.load().get(&C::id()) {
            None => {
                self.register::<C>();
                Vec::new()
            },
            Some(instances) => instances.values().filter_map(|i| {
                let instance = i.downcast::<C>().unwrap();
                if instance.pending.load().1.is_some() {
                    Some(instance.clone())
                } else {None}
            }).collect()
        }
    }

    pub async fn listen(&mut self) -> AnyInstance {self.0.listen().await}
    pub fn get_next(&mut self) -> Option<AnyInstance> {self.0.get_update()}
}

///Keeps track of my Context and their locations for recovery, (Scanning my inbox, creating new
///channels, storing and listening for new instances. Air never touches a contract Init
pub struct Manager {
    instances: Instances,
    cache: Cache,
    root: Root,
    inbox: InboxHandler,
    joinset: JoinSet<(Id, Stream, u64, Event)>,
    sinks: BTreeMap<Id, Sink>,
}

impl Manager {
    pub fn start(air: Air) -> Instances {
        let cache = Cache::new(format!("./{}/{}.db", air.name, air.name)).unwrap();
        let root = cache.get::<Root>("root").unwrap().unwrap_or_default();

        let inbox = root.inbox.start(air.clone());
        let instances = Instances(Ams::new(BTreeMap::new()), Ams::new(BTreeMap::new()), air.clone());
        let i = instances.clone();

        air.handle.clone().spawn(async move {
            let mut manager = Manager{sinks: BTreeMap::new(), cache, root, inbox, joinset: JoinSet::new(), instances};
            let keys = manager.root.contracts.keys().copied().collect::<Vec<_>>();
            for id in keys {
                manager.register(id);
            }
            manager.run().await
        });
        i
    }

    fn register(&mut self, id: Id) -> &mut HashSet<Location> {
        &mut self.root.contracts.entry(id).or_insert_with(|| {
            let air = self.instances.2.clone();
            let secret = air.secret.derive(&[id]);
            let channel = Channel::new(secret.harden());
            let (mut stream, sink) = channel.start(air, secret);
            self.sinks.insert(id, sink);
            self.joinset.spawn(async move {
                let (time, namedata) = stream.read().await;
                (id, stream, time, namedata)
            });
            (channel, HashSet::default())
        }).1
    }

    async fn store(&mut self, location: Location, write: bool) {
        let locations = self.register(location.contract_id);
        if locations.insert(location) {
            let sink = self.sinks.get(&location.contract_id).unwrap();
            if write {sink.write(postcard::to_allocvec(&location).unwrap()).await;}
        }
    }

    async fn run(mut self) {
        loop {
            tokio::select!{ biased;
                c_id = self.instances.1.listen() => {
                    for location in self.register(c_id).iter().copied().collect::<Vec<_>>() { 
                        self.instances.build(location).expect("False Register");
                    }
                },
                instance = self.instances.0.listen() => {self.store(instance.1, true).await},
                (_, location) = self.inbox.read() => {
                    self.root.inbox = *self.inbox.inbox();
                    if let Some(location) = location.and_then(|l| postcard::from_bytes(&l).ok()) {
                        self.store(location, true).await;
                        self.instances.build(location);
                    }
                },
                Some(Ok((id, mut stream, _, event))) = self.joinset.join_next() => {
                    self.root.contracts.get_mut(&id).unwrap().0 = *stream.channel();

                    if let Event::Data(_, data, _) = event 
                    && let Ok((contract_hash, key)) = postcard::from_bytes::<(Id, SecretKey)>(&data) {
                        let location = Location{key, contract_id: id, contract_hash};
                        self.store(location, false).await;
                        self.instances.build(location);
                    }

                    self.joinset.spawn(async move {
                        let (time, namedata) = stream.read().await;
                        (id, stream, time, namedata)
                    });
                },
                else => {}
            }           
            self.cache.insert("root", &self.root).unwrap();
        }
    }
}

#[derive(Clone, Debug, Copy)]
pub struct Metadata {
    pub signer: Name,
    pub timestamp: u64,
    pub confirmed: bool
}
impl Metadata {
    fn pending(signer: Name) -> Self {Metadata{signer, timestamp: now(), confirmed: false}}
    fn confirmed(signer: Name, timestamp: u64) -> Self {Metadata{signer, timestamp, confirmed: true}}
}

#[derive(Serialize, Deserialize, Hash, Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) struct Location {
    pub key: SecretKey,
    //pub servers: Vec<Name>,
    pub contract_id: Id,
    pub contract_hash: Id
}
impl Location {
    pub fn new<C: Contract>(secret: &Secret, init: &C::Init) -> Self {
        let c_id = C::id();
        let hash = Id::hash(&init);
        let key = secret.derive(&[c_id, hash]).harden();
        Location{key, contract_id: c_id, contract_hash: hash}
    }
}

#[derive(Serialize, Deserialize, Default, Debug)]
struct Root {
    inbox: Inbox,
    contracts: BTreeMap<Id, (Channel, HashSet<Location>)>,
}
