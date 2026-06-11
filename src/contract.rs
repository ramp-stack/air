use crate::names::{Id, Secret, Name, secp256k1::SecretKey, now};

use crate::channel::{Inbox, InboxHandler, Sink, Stream, Channel, Data};
use crate::cache::Cache;
use crate::Air;

use std::collections::{HashSet, BTreeMap, VecDeque};
use std::hash::Hash;
use std::any::TypeId;
use std::sync::Arc;
use std::pin::Pin;
use std::any::Any;
use std::fmt::Debug;
use std::hash::Hasher;

use serde::{Serialize, Deserialize};

use crossfire::{MAsyncTx, AsyncRx, mpsc};
use tokio::spawn;

use futures_util::stream::FuturesUnordered;
use futures_util::StreamExt;
use crate::ams::{Ams, Ref};

type PBFut<T> = Pin<Box<dyn Future<Output = T> + Send>>;
type GetUpdate = Box<dyn Fn() -> Box<dyn Any> + Send + Sync>;

pub trait Contract: Serialize + for<'a> Deserialize<'a> + Send + Sync + Clone + Debug + 'static {
    type Init: Serialize + for<'a> Deserialize<'a> + Hash + Send + Sync;
    fn init(init: Self::Init, signer: Name, timestamp: u64) -> Self;

    fn id() -> Id;

    fn reactants() -> Reactants<Self>;
}

pub trait Reactant<C: Contract>: Serialize + for<'a> Deserialize<'a> + Send + Sync + Clone + Debug + 'static {
    type Result: 'static + Sync + Send + Clone;

    fn id() -> Id;

    fn apply(self, model: &mut C, signer: Name, timestamp: u64) -> Self::Result;
}

#[derive(Clone)]
pub struct Update(Id, Arc<GetUpdate>);
impl Update {
    fn new<C: Contract, R: Reactant<C>>(result: R::Result) -> Self {
        Update(R::id(), Arc::new(Box::new(move || Box::new(result.clone()) as Box<dyn Any>)))
    }

    pub fn as_reactant<C: Contract, R: Reactant<C>>(&self) -> Option<R::Result> {
        (self.0 == R::id()).then(|| *(self.1)().downcast::<R::Result>().unwrap())
    }

    pub fn reactant_id(&self) -> Id {self.0}
}
impl std::fmt::Debug for Update {fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.debug_tuple("Update").field(&self.0).finish()
}}

#[derive(Clone)]
pub struct Instance<C: Contract>{
    id: Id,
    air: Air,
    sink: Sink,
    location: Location,
    reactants: Arc<Reactants<C>>,
    confirmed: Ams<Option<C>, Update>,
    pending: Ams<(VecDeque<ErasedReactant<C>>, Option<C>), ()>,
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
        if let Some(init) = init.as_ref() {
            sink.write_sync(postcard::to_allocvec(&(id, postcard::to_allocvec(init).unwrap())).unwrap());
        }
        let reactants = Arc::new(C::reactants());
        let confirmed = Ams::new(contract.clone());
        let pending = Ams::new((VecDeque::new(), contract.or(init.map(|i| C::init(i, air.name, now())))));
        let instance = Instance{sink, air: air.clone(), id, location, reactants, confirmed, pending};
        air.handle.spawn(instance.clone().run(cache, stream));
        instance
    }

    pub fn share(&self, name: Name) {
        InboxHandler::send(self.air.clone(), name, postcard::to_allocvec(&self.location).unwrap());
    }

    pub fn confirmed_update(&mut self) -> Option<Update> {
        self.confirmed.get_update()
    }

    pub fn clear_confirmed(&mut self) {
        self.confirmed.clear_updates();
    }

    pub fn pending_updated(&mut self) -> bool {
        let r = self.pending.get_update().is_some();
        self.pending.clear_updates();
        r
    }

    pub async fn listen_pending(&mut self) {
        self.pending.listen().await
    }
    pub async fn listen_confirmed(&mut self) -> Update {
        self.confirmed.listen().await
    }
    pub fn pending(&self) -> Ref<'_, C> {
        self.pending.load_partial(|i: &(VecDeque<ErasedReactant<C>>, Option<C>)| i.1.as_ref().unwrap())
    }
    pub fn confirmed(&self) -> Option<Ref<'_, C>> {
        let r = self.confirmed.load();
        r.is_some().then(|| r.map(|c: &Option<C>| c.as_ref().unwrap()))
    }

    pub fn try_apply<O, E, R: Reactant<C, Result = Result<O, E>>>(&mut self, reactant: R) -> Result<O, E> {
        self.reactants.id::<R>().expect("Reactant is not listed in Contract::reactants()");
        let mut r = None;
        self.pending.try_lock(|pending: &mut (VecDeque<ErasedReactant<C>>, Option<C>)| {
            let bytes = postcard::to_allocvec(&reactant).unwrap();
            r = Some(reactant.clone().apply(pending.1.as_mut().unwrap(), self.air.name, now())?);
            let erased = ErasedReactant::new(reactant, bytes);
            self.sink.write_sync(erased.serialize());
            pending.0.push_back(erased);
            Ok(())
        }, true)?;
        Ok(r.unwrap())
    }

    pub fn apply<R: Reactant<C>>(&mut self, reactant: R) -> R::Result {
        self.reactants.id::<R>().expect("Reactant is not listed in Contract::reactants()");
        let mut r = None;
        self.pending.lock(|pending: &mut (VecDeque<ErasedReactant<C>>, Option<C>)| {
            let bytes = postcard::to_allocvec(&reactant).unwrap();
            r = Some(reactant.clone().apply(pending.1.as_mut().unwrap(), self.air.name, now()));
            let erased = ErasedReactant::new(reactant, bytes);
            self.sink.write_sync(erased.serialize());
            pending.0.push_back(erased);
        }, true);
        r.unwrap()
    }

    async fn run(mut self, mut cache: Cache, mut stream: Stream) {
        loop {
            let (time, namedata) = stream.read().await;
            if let Some((name, data)) = namedata
            && let Ok((id, bytes)) = postcard::from_bytes::<(Id, Vec<u8>)>(&data) {
                if self.confirmed.load().is_none() {
                    if id == self.id && let Ok(init) = postcard::from_bytes(&bytes) {
                        self.confirmed.store(Some(C::init(init, name, time)));
                    } else {
                        println!("Invalid Contract Init");
                    }
                } else if id == self.id {
                    println!("tried to init contract twice");
                } else if let Some(reactant) = self.reactants.deserialize(&id, bytes) {
                    self.pending.lock(|pending: &mut (VecDeque<ErasedReactant<C>>, Option<C>)| {
                        self.confirmed.lock(|confirmed: &mut Option<C>| {
                            let update = reactant.apply(confirmed.as_mut().unwrap(), name, time);
                            pending.1 = confirmed.clone();
                            let queue = &mut pending.0;
                            if queue.front().map(|r| Id::hash(&r) == Id::hash(&reactant)).unwrap_or_default() {
                                queue.pop_front();
                            }
                            let (queue, sub) = &mut *pending;
                            for r in queue {
                                r.apply(sub.as_mut().unwrap(), self.air.name, now());
                            }
                            update
                        }, true);
                    }, true);
                }
            }
            cache.insert("instance", &(&stream.channel(), &*self.confirmed.load())).unwrap();
        }
    }
}

#[derive(Clone)]
pub struct DynInstance(Id, Id, Arc<Box<dyn Any + Send + Sync>>);
impl DynInstance {
    fn new<C: Contract>(instance: Instance<C>) -> Self {
        DynInstance(C::id(), instance.id, Arc::new(Box::new(instance)))
    }
    pub fn as_contract<C: Contract>(&self) -> Option<Instance<C>> {
        (self.0 == C::id()).then(|| self.2.downcast_ref::<Instance<C>>().unwrap().clone())
    }
}
impl Debug for DynInstance {fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.debug_struct("Instance").field("contract_id", &self.0).field("id", &self.1).finish()
}}

type Instances = BTreeMap<Id, BTreeMap<Id, DynInstance>>;

#[derive(Clone)]
pub struct Context {
    air: Air,
    tx: MAsyncTx<mpsc::List<Request>>,
    instances: Ams<Instances, DynInstance>,
}

impl Context {
    pub fn me(&self) -> Name {self.air.name}

    pub fn register<C: Contract>(&self) {
        let all = self.instances.clone();
        self.tx.try_send(Request::Register(C::id(), InstanceBuilder::new::<C>(self.air.clone(), all))).unwrap();
    }

    pub fn list<C: Contract>(&mut self) -> Vec<Instance<C>> {
        match self.instances.load().get(&C::id()) {
            None => {
                self.register::<C>();
                Vec::new()
            },
            Some(map) => map.values().filter_map(|i| {
                let instance = i.as_contract::<C>().unwrap();
                if instance.pending.load().1.is_some() {
                    Some(instance.clone())
                } else {None}
            }).collect()
        }
    }

    pub async fn listen(&mut self) -> DynInstance {
        self.instances.listen().await
    }

    pub async fn get_new_instance(&mut self) -> Option<DynInstance> {
        self.instances.get_update()
    }

    pub fn create<C: Contract>(&mut self, init: C::Init) -> Instance<C> {
        let c_id = C::id();
        let location = Location::new::<C>(&self.air.secret, &init);
        let id = Id::hash(&location);
        let instance = self.instances.load().get(&c_id).and_then(|i| i.get(&id)).map(|i| i.as_contract::<C>().unwrap());
        match instance {
            Some(instance) => instance,
            None => {
                let all = self.instances.clone();
                self.instances.lock(|instances: &mut Instances| {
                    instances.entry(c_id).or_insert_with(|| {
                        self.tx.try_send(Request::Register(c_id, InstanceBuilder::new::<C>(self.air.clone(), all))).unwrap();
                        BTreeMap::default()
                    }).entry(id).or_insert_with(|| {
                        let instance = Instance::<C>::start(self.air.clone(), location, Some(init));
                        self.tx.try_send(Request::New(location)).unwrap();
                        DynInstance::new(instance)
                    }).clone()
                }, false).as_contract::<C>().unwrap()
            }
        }
    }
}

enum Request {New(Location), Register(Id, InstanceBuilder)}

///Keeps track of my Contracts and their locations for recovery, (Scanning my inbox, creating new
///channels, storing and listening for new instances. Air never touches a contract Init
pub struct Manager {
    context: Context,
    cache: Cache,
    root: Root,
    rx: AsyncRx<mpsc::List<Request>>,
    inbox: InboxHandler,
    futures: FuturesUnordered<PBFut<(Id, Stream, u64, Data)>>,
    contracts: BTreeMap<Id, (Option<InstanceBuilder>, Sink)>,
}

impl Manager {
    pub fn start(air: Air) -> Context {
        let cache = Cache::new(format!("./{}/{}.db", air.name, air.name)).unwrap();
        let root = cache.get::<Root>("root").unwrap().unwrap_or_default();

        let (tx, rx) = mpsc::build(mpsc::List::new());
        let inbox = root.inbox.start(air.clone());

        let instances = Ams::new(root.contracts.keys().map(|id| (*id, BTreeMap::new())).collect());

        let context = Context{instances, air, tx};
        let air = context.clone();

        spawn(async move {
            let futures = FuturesUnordered::new();
            let contracts = root.contracts.iter().map(|(id, (channel, _))| {
                let (mut stream, sink) = channel.start(context.air.clone(), context.air.secret.clone());
                let id = *id;
                futures.push(Box::pin(async move {
                    let (time, namedata) = stream.read().await;
                    (id, stream, time, namedata)
                }) as _);
                (id, (None, sink))
            }).collect();
            Manager{context, cache, root, rx, inbox, futures, contracts}.run().await
        });

        air 
    }

    fn contract(&mut self, id: Id) -> &mut (Channel, HashSet<Location>) {
        self.root.contracts.entry(id).or_insert_with(|| {
            let secret = self.context.air.secret.derive(&[id]);
            let channel = Channel::new(secret.harden());
            let (mut stream, sink) = channel.start(self.context.air.clone(), secret);
            self.contracts.insert(id, (None, sink));
            self.futures.push(Box::pin(async move {
                let (time, namedata) = stream.read().await;
                (id, stream, time, namedata)
            }) as _);
            (channel, HashSet::default())
        })
    }

    async fn add(&mut self, location: Location, post_local: bool, store: bool) {
        let entry = self.contract(location.contract_id);
        if entry.1.insert(location) {
            let (_, sink) = self.contracts.get(&location.contract_id).unwrap();
            if store {sink.write(postcard::to_allocvec(&location).unwrap()).await;}
            let (receiver, _) = self.contracts.get(&location.contract_id).unwrap();
            if post_local && let Some(builder) = receiver.as_ref() {
                (builder.0)(location).await;
            }
        }
    }

    async fn run(mut self) {
        loop {
            tokio::select!{ biased;
                Ok(request) = self.rx.recv() => match request {
                    //Register new contracts and new instances???
                    Request::Register(id, builder) => {
                        for location in &self.contract(id).1 { 
                            (builder.0)(*location).await;
                        }
                        self.contracts.get_mut(&id).unwrap().0 = Some(builder);
                    },
                    Request::New(location) => {self.add(location, false, true).await;}
                },
                (_, location) = self.inbox.read() => {
                    self.root.inbox = *self.inbox.inbox();
                    if let Some(location) = location.and_then(|l| postcard::from_bytes(&l).ok()) {self.add(location, true, true).await}
                },
                Some((id, mut stream, _, namedata)) = self.futures.next() => {
                    self.root.contracts.get_mut(&id).unwrap().0 = *stream.channel();

                    if let Some((_, data)) = namedata 
                    && let Ok((contract_hash, key)) = postcard::from_bytes::<(Id, SecretKey)>(&data) {
                        let location = Location{key, contract_id: id, contract_hash};
                        self.add(location, true, false).await;
                    }

                    self.futures.push(Box::pin(async move {
                        let (time, namedata) = stream.read().await;
                        (id, stream, time, namedata)
                    }) as _);
                },
                else => {}
            }           
            self.cache.insert("root", &self.root).unwrap();
        }
    }
}

type ReactantApply<C> = Box<dyn Fn(&mut C, Name, u64) -> Update + Send + Sync>;

#[allow(clippy::type_complexity)]
#[derive(Clone)]
struct ErasedReactant<C>(Arc<ReactantApply<C>>, Id, Vec<u8>);
impl<C: Contract> ErasedReactant<C> {
    fn new<R: Reactant<C>>(reactant: R, bytes: Vec<u8>) -> Self {
        ErasedReactant(Arc::new(Box::new(move |model: &mut C, signer: Name, timestamp: u64|
            Update::new::<C, R>(reactant.clone().apply(model, signer, timestamp))
        )), R::id(), bytes)
    }
    fn serialize(&self) -> Vec<u8> {postcard::to_allocvec(&(&self.1, &self.2)).unwrap()}
    fn apply(&self, model: &mut C, signer: Name, timestamp: u64) -> Update {(self.0)(model, signer, timestamp)}
}
impl<C: Contract> Hash for ErasedReactant<C> {
    fn hash<H: Hasher>(&self, state: &mut H) {self.1.hash(state); self.2.hash(state);}
}
impl<C: Contract> std::fmt::Debug for ErasedReactant<C> {fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.debug_struct("ErasedReactant").field("contract_id", &C::id()).field("reactant_id", &self.1).finish()
}}

type GetReactant<C> = Box<dyn Fn(Vec<u8>) -> Result<ErasedReactant<C>, postcard::Error> + Send + Sync>;

pub struct Reactants<C>(BTreeMap<Id, (TypeId, String, GetReactant<C>)>);
impl<C: Contract> std::fmt::Debug for Reactants<C> {fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.debug_map().entries(self.0.iter().map(|(id, i)| (id, &i.1))).finish()
}}
impl<C: Contract> Default for Reactants<C> {fn default() -> Self {Reactants(BTreeMap::default())}}
impl<C: Contract> Reactants<C> {
    pub fn add<R: Reactant<C>>(mut self) -> Self {
        let id = R::id();
        self.0.insert(id, (TypeId::of::<R>(), std::any::type_name::<R>().to_string(), Box::new(move |bytes: Vec<u8>|
            Ok(ErasedReactant::new(postcard::from_bytes::<R>(&bytes)?, bytes))
        )));
        self
    } 

    fn id<R: Reactant<C> + 'static>(&self) -> Option<Id> {
        let ty_id = TypeId::of::<R>();
        self.0.iter().find_map(|(id, (ty, _, _))| (*ty == ty_id).then_some(*id))
    }

    fn deserialize(&self, id: &Id, bytes: Vec<u8>) -> Option<ErasedReactant<C>> {
        match self.0.get(id) {
            Some((_, _, getter)) => match (getter)(bytes) {
                Ok(erased) => {return Some(erased);},
                Err(e) => println!("Error Deserializing Reactant: {e:?}")
            },
            None => println!("Reactant Had Unknown Id: {id}")
        }
        None
    }
}

pub struct Listner<C: Contract>(BTreeMap<Id, Instance<C>>);
    impl<C: Contract> Listner<C> {
        pub async fn listen(&mut self, ctx: &mut Context) -> (&mut Instance<C>, Option<Update>) {
            if self.0.is_empty() && let Some(room) = ctx.listen().await.as_contract::<C>() {
                (self.0.entry(room.id()).or_insert(room), None)
            } else { loop {
                let mut pending = self.0.values_mut().map(|instance| async {
                    (instance.listen_confirmed().await, instance.id())
                }).collect::<FuturesUnordered<_>>();

                tokio::select! { biased;
                    instance = ctx.listen() => {
                        drop(pending);
                        if let Some(room) = instance.as_contract::<C>() {
                            break (self.0.entry(room.id()).or_insert(room), None)
                        }
                    },
                    Some((update, id)) = pending.next() => {
                        drop(pending);
                        break (self.0.get_mut(&id).unwrap(), Some(update));
                    },
                }
            }}
        }
    }
    impl<C: Contract> Default for Listner<C> {fn default() -> Self {Self(BTreeMap::default())}}

struct InstanceBuilder(Box<dyn Fn(Location) -> PBFut<()> + Send + Sync>);
impl InstanceBuilder {
    pub fn new<C: Contract>(air: Air, instances: Ams<Instances, DynInstance>) -> Self {
        InstanceBuilder(Box::new(move |location: Location| {
            let air = air.clone();
            let mut instances = instances.clone();
            Box::pin(async move {
                let c_id = C::id();
                let id = Id::hash(&location);
                if !instances.load().get(&c_id).map(|g| g.contains_key(&id)).unwrap_or_default() {
                    instances.lock(|instances: &mut Instances| {
                        instances.entry(c_id).or_default().entry(id).or_insert_with(|| {
                            DynInstance::new(Instance::<C>::start(air.clone(), location, None))
                        }).clone()
                    }, false);
                }
            })
        }))
    }
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
        let secret = secret.derive(&[c_id, hash]);
        let key = secret.harden();
        Location{key, contract_id: c_id, contract_hash: hash}
    }
}

#[derive(Serialize, Deserialize, Default, Debug)]
struct Root {
    inbox: Inbox,
    contracts: BTreeMap<Id, (Channel, HashSet<Location>)>,
}
