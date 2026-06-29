use crate::names::{Id, Secret, Name, secp256k1::SecretKey, now};

use crate::channel::{Inbox, InboxHandler, Sink, Stream, Channel, Event};
use crate::cache::Cache;
use crate::Air;

use std::collections::{HashSet, BTreeMap, VecDeque};
use std::hash::Hash;
use std::any::TypeId;
use std::sync::Arc;
use std::pin::Pin;
use std::task::Poll;
use std::any::Any;
use std::fmt::Debug;
use std::hash::Hasher;

use serde::{Serialize, Deserialize};

use crossfire::{MAsyncTx, AsyncRx, mpsc};

use futures_util::stream::FuturesUnordered;
use futures_util::StreamExt;
use crate::ams::{Ams, Ref};

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

type PBFut<T> = Pin<Box<dyn Future<Output = T> + Send>>;
type GetUpdate = Box<dyn Fn() -> Box<dyn Any> + Send + Sync>;

pub trait Contract: Serialize + for<'a> Deserialize<'a> + Send + Sync + Clone + Debug + 'static {
    type Init: Serialize + for<'a> Deserialize<'a> + Hash + Send + Sync;
    fn init(init: Self::Init, metadata: Metadata) -> Self;

    fn id() -> Id;

    fn reactants() -> Reactants<Self>;
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, Hash)]
pub enum Increatable {}

#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
pub struct AnyContract;
impl Contract for AnyContract {
    type Init = Increatable;
    fn init(_: Self::Init, _: Metadata) -> Self {AnyContract}
    fn id() -> Id {Id::hash(&"")}
    fn reactants() -> Reactants<Self> {Reactants::default()}
}

pub trait Reactant<C: Contract>: Serialize + for<'a> Deserialize<'a> + Send + Sync + Clone + Debug + 'static {
    type Result: 'static + Sync + Send + Clone + Debug;

    fn id() -> Id;

    fn apply(self, model: &mut C, metadata: Metadata) -> Self::Result;
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, Hash)]
pub enum AnyReactant {}
impl<C: Contract> Reactant<C> for AnyReactant {
    type Result = DynResult;
    fn id() -> Id {Id::hash(&"")}
    fn apply(self, _: &mut C, _: Metadata) -> Self::Result {
        panic!("Do not apply the special AnyReactant to a contract, duuuuh.")
    }
}

#[derive(Clone)]
pub struct DynResult(Id, Arc<GetUpdate>);
impl DynResult {
    fn new<C: Contract, R: Reactant<C>>(result: R::Result) -> Self {
        DynResult(R::id(), Arc::new(Box::new(move || Box::new(result.clone()) as Box<dyn Any>)))
    }

    pub fn as_reactant<C: Contract, R: Reactant<C>>(&self) -> Option<R::Result> {
        if TypeId::of::<R>() == TypeId::of::<AnyReactant>() {
            let result = self.clone();
            let casted: R::Result = unsafe {
                std::ptr::read(&result as *const DynResult as *const R::Result)
            };
            std::mem::forget(result);
            Some(casted)
        } else {
            (self.0 == R::id()).then(|| *(self.1)().downcast::<R::Result>().unwrap())
        }
    }

    pub fn reactant_id(&self) -> Id {self.0}
}
impl std::fmt::Debug for DynResult {fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.debug_tuple("DynResult").field(&self.0).finish()
}}

pub enum PendingResult<O: Debug + Clone + Sync + Send + 'static, E: Debug + Clone + Sync + Send + 'static> {
    Ok(Pending<Result<O, E>>),
    Err(E)
}
impl<O: Debug + Clone + Sync + Send + 'static, E: Debug + Clone + Sync + Send + 'static> Future for PendingResult<O, E> {
    type Output = Result<O, E>;
    fn poll(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Self::Output> {
        unsafe { match &mut *self.get_unchecked_mut() {
            Self::Ok(pending) => Pin::new_unchecked(pending).poll(cx),
            Self::Err(err) => Poll::Ready(Err(err.clone())),
        }}
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Pending<R: Debug + Clone + Sync + Send + 'static>(Ams<(R, bool), bool>);
impl<R: Debug + Clone + Sync + Send + 'static> Pending<R> {
    fn new(result: R) -> Self {Pending(Ams::new((result, false)))}

    pub fn is_confirmed(&self) -> bool {self.0.load().1}
    pub fn load(&self) -> Ref<R> {self.0.load_partial(|r: &(R, bool)| &r.0)}
    pub fn get_update(&mut self) -> Option<bool> {self.0.get_update()}

    fn update(&mut self, result: R, confirmed: bool) {
        let mut lock = self.0.lock();
        *lock = (result, confirmed);
        lock.commit(confirmed);
    }
}
impl<R: Debug + Clone + Sync + Send + 'static> Future for Pending<R> {
    type Output = R;
    fn poll(mut self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Self::Output> {
        {
            let fut = self.0.listen();
            tokio::pin!(fut);
            if matches!(fut.as_mut().poll(cx), Poll::Pending) {return Poll::Pending;}
        }
        Poll::Ready(self.load().clone())
    }
}

type Queue<C> = VecDeque<(Id, ErasedReactant<C>)>;

pub struct Instance<C: Contract>{
    id: Id,
    air: Air,
    sink: Sink,
    location: Location,
    reactants: Arc<Reactants<C>>,
    confirmed: Ams<Option<C>, (Id, DynResult)>,
    pending: Ams<(Queue<C>, Option<C>), Id>,
    sent: Vec<Id>,
    head: Ams<bool, bool>
}

impl<C: Contract> Clone for Instance<C> {fn clone(&self) -> Self {Instance{
    id: self.id,
    air: self.air.clone(),
    sink: self.sink.clone(),
    location: self.location,
    reactants: self.reactants.clone(),
    confirmed: self.confirmed.clone(),
    pending: self.pending.clone(),
    sent: Vec::new(),
    head: self.head.clone() 
}}}

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
            sink.write_sync(Id::random(), postcard::to_allocvec(&(id, postcard::to_allocvec(init).unwrap())).unwrap());
        }
        let reactants = Arc::new(C::reactants());
        let confirmed = Ams::new(contract.clone());
        let pending = Ams::new((VecDeque::new(), contract.or(init.map(|i| C::init(i, Metadata::pending(air.name))))));
        let head = Ams::new(false);
        let instance = Instance{sink, air: air.clone(), id, location, reactants, confirmed, pending, head, sent: Vec::new()};
        air.handle.spawn(instance.clone().run(cache, stream));
        instance
    }

    pub fn share(&self, name: Name) {
        InboxHandler::send(self.air.clone(), name, postcard::to_allocvec(&self.location).unwrap());
    }

    pub fn clear_confirmed(&mut self) { self.confirmed.clear_updates(); }
    pub fn clear_pending(&mut self) { self.pending.clear_updates(); }
    pub fn clear_updates(&mut self) { self.clear_confirmed(); self.clear_pending(); }

   
    pub fn confirmed_update<R: Reactant<C>>(&mut self) -> Option<R::Result> {
        let update = self.confirmed.get_update();
        update.and_then(|(id, r)| (!self.sent.contains(&id)).then_some(r))?.as_reactant::<_, R>()
    }

    pub async fn listen_confirmed<R: Reactant<C>>(&mut self) -> R::Result {
        loop {
            let (id, update) = self.confirmed.listen().await;
            if let Some(Some(result)) = (!self.sent.contains(&id)).then(|| update.as_reactant::<_, R>()) {
                break result;
            }
        }
    }

    ///Is this ever None? If the Hash of C deterimans the Key I could throw an error if it turns
    ///out not to be the original C
    pub fn confirmed(&self) -> Option<Ref<C>> {
        let r: Ref<Option<C>> = self.confirmed.load();
        r.is_some().then(|| r.map(|c: &Option<C>| c.as_ref().unwrap()))
    }

    pub fn pending_updated(&mut self) -> bool {
        let r = self.pending.get_update().is_some();
        self.pending.clear_updates();
        r
    }

    pub async fn listen_pending(&mut self) {
        self.pending.listen().await;
    }

    pub fn pending(&self) -> Ref<C> {
        self.pending.load_partial(|i: &(VecDeque<(Id, ErasedReactant<C>)>, Option<C>)| i.1.as_ref().unwrap())
    }

    ///If true then confirmed will always return Some(_) and we have read at least one empty message in the channel
    ///therefore any new confirmed reactants are either en route or will be returned by confirmed_update
    pub fn is_initialized(&self) -> bool {*self.head.load()}

    ///If the outer result is Err the reactant has not been sent and will not update its state in the future
    pub fn try_apply<O: Send + Sync + Clone + Debug, E: Sync + Send + Clone + Debug, R: Reactant<C, Result = Result<O, E>>>(&mut self, reactant: R) -> PendingResult<O, E> {
        self.reactants.id::<R>().expect("Reactant is not listed in Contract::reactants()");
        let mut pending = self.pending.lock();
        let bytes = postcard::to_allocvec(&reactant).unwrap();
        let metadata = Metadata::pending(self.air.name);
        match reactant.clone().apply(pending.1.as_mut().unwrap(), metadata) {
            Ok(ok) => {
                let result = Pending::new(Ok(ok));
                let erased = ErasedReactant::new(reactant, bytes, Some(result.clone()));
                let rid = Id::random();
                self.sink.write_sync(rid, erased.serialize());
                pending.0.push_back((rid, erased));
                self.sent.push(rid);
                pending.commit(rid);
                PendingResult::Ok(result)
            },
            Err(err) => PendingResult::Err(err)
        }
    }

    pub fn apply<R: Reactant<C>>(&mut self, reactant: R) -> Pending<R::Result> {
        self.reactants.id::<R>().expect("Reactant is not listed in Contract::reactants()");
        let mut pending = self.pending.lock();
        let bytes = postcard::to_allocvec(&reactant).unwrap();
        let metadata = Metadata::pending(self.air.name);
        let result = Pending::new(reactant.clone().apply(pending.1.as_mut().unwrap(), metadata));
        let erased = ErasedReactant::new(reactant, bytes, Some(result.clone()));
        let rid = Id::random();
        self.sink.write_sync(rid, erased.serialize());
        pending.0.push_back((rid, erased));
        self.sent.push(rid);
        pending.commit(rid);
        result
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
                        } else if id == self.id {
                            println!("tried to init contract twice");
                        } else if let Some(reactant) = self.reactants.deserialize(&id, bytes) {
                            let mut pending = self.pending.lock();
                            let mut confirmed = self.confirmed.lock();
                            let queue = &mut pending.0;
                            let (rid, update) = if let Some(rid) = rid && queue.front().map(|(request_id, _)| *request_id == rid).unwrap_or_default() {
                                (rid, queue.pop_front().unwrap().1.apply(confirmed.as_mut().unwrap(), metadata))
                            } else {(Id::random(), reactant.apply(confirmed.as_mut().unwrap(), metadata))};
                            pending.1 = confirmed.clone();
                            let (queue, sub) = &mut *pending;
                            for (_, r) in queue {
                                r.apply(sub.as_mut().unwrap(), Metadata::pending(self.air.name));
                            }
                            pending.commit(rid);
                            confirmed.commit((rid, update));
                        }
                    }
                },
                Event::Garbage => {}
            }
            cache.insert("instance", &(&stream.channel(), &*self.confirmed.load())).unwrap();
        }
    }

    pub async fn wait_for_initialized(&mut self) -> Ref<C> {
        loop { if *self.head.load() {break;} self.head.listen().await;}
        self.confirmed().unwrap()
    }
}
//  impl<C: Contract> Future for Instance<C> {
//      type Output = Ref<'_, C>;
//      fn poll(mut self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Self::Output> {
//          {
//              let fut = self.0.listen();
//              tokio::pin!(fut);
//              if matches!(fut.as_mut().poll(cx), Poll::Pending) {return Poll::Pending;}
//          }
//          Poll::Ready(self.load().clone())
//      }
//  }

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
    pub(crate) air: Air,
    tx: MAsyncTx<mpsc::List<Request>>,
    instances: Ams<Instances, DynInstance>,
}

impl Context {
    pub fn me(&self) -> Name {self.air.name}
    pub fn service_secret<S: crate::Service>(&self) -> Secret {self.air.service_secret::<S>()}

    pub fn register<C: Contract>(&self) {
        self.tx.try_send(Request::Register(C::id(), InstanceBuilder::new::<C>(self.air.clone(), self.instances.clone()))).unwrap();
    }

    pub fn list<C: Contract>(&self) -> Vec<Instance<C>> {
        match self.instances.load().get(&C::id()) {
            None => {
                self.register::<C>();
                Vec::new()
            },
            Some(map) => map.values().filter_map(|i| {
                let instance = i.as_contract::<C>().unwrap();
                if instance.pending.load().1.is_some() {
                    let mut instance = instance.clone();
                    instance.confirmed.clear_updates();
                    instance.pending.clear_updates();
                    instance.head.clear_updates();
                    Some(instance)
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

    pub fn create<C: Contract>(&self, init: C::Init) -> Instance<C> {
        let c_id = C::id();
        let location = Location::new::<C>(&self.air.secret, &init);
        let id = Id::hash(&location);
        let instance = self.instances.load().get(&c_id).and_then(|i| i.get(&id)).map(|i| i.as_contract::<C>().unwrap());
        match instance {
            Some(instance) => instance,
            None => {
                let all = self.instances.clone();
                let mut instances = self.instances.lock();
                let instance = instances.entry(c_id).or_insert_with(|| {
                    self.tx.try_send(Request::Register(c_id, InstanceBuilder::new::<C>(self.air.clone(), all))).unwrap();
                    BTreeMap::default()
                }).entry(id).or_insert_with(|| {
                    let instance = Instance::<C>::start(self.air.clone(), location, Some(init));
                    self.tx.try_send(Request::New(location)).unwrap();
                    DynInstance::new(instance)
                }).clone();
                instances.commit(instance.clone());
                instance.as_contract::<C>().unwrap()
            }
        }
    }
}

enum Request {New(Location), Register(Id, InstanceBuilder)}

///Keeps track of my Context and their locations for recovery, (Scanning my inbox, creating new
///channels, storing and listening for new instances. Air never touches a contract Init
pub struct Manager {
    contracts: Context,
    cache: Cache,
    root: Root,
    rx: AsyncRx<mpsc::List<Request>>,
    inbox: InboxHandler,
    futures: FuturesUnordered<PBFut<(Id, Stream, u64, Event)>>,
    builders: BTreeMap<Id, (Option<InstanceBuilder>, Sink)>,
}

impl Manager {
    pub fn start(air: Air) -> Context {
        let cache = Cache::new(format!("./{}/{}.db", air.name, air.name)).unwrap();
        let root = cache.get::<Root>("root").unwrap().unwrap_or_default();

        let (tx, rx) = mpsc::build(mpsc::List::new());
        let inbox = root.inbox.start(air.clone());
        let instances = Ams::new(BTreeMap::new());
        let contracts = Context{instances, air, tx};
        let c = contracts.clone();

        contracts.air.handle.clone().spawn(async move {
            let futures = FuturesUnordered::new();
            let builders = root.contracts.iter().map(|(id, (channel, _))| {
                let (mut stream, sink) = channel.start(contracts.air.clone(), contracts.air.secret.clone());
                let id = *id;
                futures.push(Box::pin(async move {
                    let (time, event) = stream.read().await;
                    (id, stream, time, event)
                }) as _);
                (id, (None, sink))
            }).collect();
            Manager{builders, cache, root, rx, inbox, futures, contracts}.run().await
        });
        c
    }

    fn contract(&mut self, id: Id) -> &mut (Channel, HashSet<Location>) {
        self.root.contracts.entry(id).or_insert_with(|| {
            let secret = self.contracts.air.secret.derive(&[id]);
            let channel = Channel::new(secret.harden());
            let (mut stream, sink) = channel.start(self.contracts.air.clone(), secret);
            self.builders.insert(id, (None, sink));
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
            let (_, sink) = self.builders.get(&location.contract_id).unwrap();
            if store {sink.write(Id::random(), postcard::to_allocvec(&location).unwrap()).await;}
            let (receiver, _) = self.builders.get(&location.contract_id).unwrap();
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
                        self.builders.get_mut(&id).unwrap().0 = Some(builder);
                    },
                    Request::New(location) => {self.add(location, false, true).await;}
                },
                (_, location) = self.inbox.read() => {
                    self.root.inbox = *self.inbox.inbox();
                    if let Some(location) = location.and_then(|l| postcard::from_bytes(&l).ok()) {self.add(location, true, true).await}
                },
                Some((id, mut stream, _, event)) = self.futures.next() => {
                    self.root.contracts.get_mut(&id).unwrap().0 = *stream.channel();

                    if let Event::Data(_, data, _) = event 
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

type GetReactant<C> = Box<dyn Fn(Vec<u8>) -> Result<ErasedReactant<C>, postcard::Error> + Send + Sync>;

pub struct Reactants<C>(BTreeMap<Id, (TypeId, String, GetReactant<C>)>);
impl<C: Contract> std::fmt::Debug for Reactants<C> {fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.debug_map().entries(self.0.iter().map(|(id, i)| (id, &i.1))).finish()
}}
impl<C: Contract> Default for Reactants<C> {fn default() -> Self {Reactants(BTreeMap::default())}}
impl<C: Contract> Reactants<C> {
    pub fn add<R: Reactant<C>>(mut self) -> Self {
        let id = R::id();
        self.0.insert(id, (TypeId::of::<R>(), std::any::type_name::<R>().to_string(), Box::new(move |bytes: Vec<u8>| {
            Ok(ErasedReactant::new(postcard::from_bytes::<R>(&bytes)?, bytes, None))
        })));
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
    pub async fn listen<R: Reactant<C>>(&mut self, contracts: &mut Context) -> (&mut Instance<C>, Option<R::Result>) {
        if self.0.is_empty() && let Some(room) = contracts.listen().await.as_contract::<C>() {
            (self.0.entry(room.id()).or_insert(room), None)
        } else { loop {
            let mut pending = self.0.values_mut().map(|instance| async {
                (instance.listen_confirmed::<R>().await, instance.id())
            }).collect::<FuturesUnordered<_>>();

            tokio::select! { biased;
                instance = contracts.listen() => {
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
            let instances = instances.clone();
            Box::pin(async move {
                let c_id = C::id();
                let id = Id::hash(&location);
                if !instances.load().get(&c_id).map(|g| g.contains_key(&id)).unwrap_or_default() {
                    let mut instances = instances.lock();
                    let instance = instances.entry(c_id).or_default().entry(id).or_insert_with(|| {
                        DynInstance::new(Instance::<C>::start(air.clone(), location, None))
                    }).clone();
                    instances.commit(instance);
                }
            })
        }))
    }
}

type ReactantApply<C> = Box<dyn Fn(&mut C, Metadata) -> DynResult + Send + Sync>;

#[derive(Clone)]
struct ErasedReactant<C>{
    apply: Arc<ReactantApply<C>>,
    reactant_id: Id,
    bytes: Vec<u8>
}
impl<C: Contract> ErasedReactant<C> {
    fn new<R: Reactant<C>>(reactant: R, bytes: Vec<u8>, pending: Option<Pending<R::Result>>) -> Self {
        ErasedReactant{
            apply: Arc::new(Box::new(move |model: &mut C, metadata: Metadata| {
                let result = reactant.clone().apply(model, metadata);
                if let Some(pending) = pending.clone().as_mut() {
                    pending.update(result.clone(), metadata.confirmed);
                }
                DynResult::new::<C, R>(result)
            })),
            reactant_id: R::id(), bytes
        }
    }
    fn serialize(&self) -> Vec<u8> {postcard::to_allocvec(&(&self.reactant_id, &self.bytes)).unwrap()}
    fn apply(&self, model: &mut C, metadata: Metadata) -> DynResult {(self.apply)(model, metadata)}
}
impl<C: Contract> Hash for ErasedReactant<C> {
    fn hash<H: Hasher>(&self, state: &mut H) {self.reactant_id.hash(state); self.bytes.hash(state);}
}
impl<C: Contract> std::fmt::Debug for ErasedReactant<C> {fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.debug_struct("ErasedReactant").field("contract_id", &C::id()).field("reactant_id", &self.reactant_id).finish()
}}

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
