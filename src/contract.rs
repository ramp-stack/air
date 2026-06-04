use crate::names::{Id, Secret, Resolver, Name, secp256k1::SecretKey, now};

use crate::channel::{Inbox, InboxHandler, Sink, Stream, Channel, Data};
use crate::server::Purser;

use std::collections::{HashSet, BTreeMap, VecDeque};
use std::path::Path;
use std::hash::Hash;
use std::any::TypeId;
use std::sync::Arc;
use std::pin::Pin;
use std::any::Any;
use std::marker::PhantomData;

use serde::{Serialize, Deserialize};

use crossfire::{MAsyncTx, AsyncRx, mpsc};
use tokio::spawn;
use tokio::sync::Mutex;

use futures_util::stream::FuturesUnordered;
use futures_util::StreamExt;
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, OpenFlags, Error};

use arc_swap::ArcSwap;
use arc_swap::strategy::DefaultStrategy;

enum Request {
    New(Location),
    Register(Id, InstanceBuilder)
}

type PBFut<T> = Pin<Box<dyn Future<Output = T> + Send>>;
type AnyInstance = Arc<Box<dyn Any + Send + Sync>>;
type ReactantApply<C> = Box<dyn Fn(&[u8], &mut C, Name, u64) -> bool + Sync + Send>;
type SerializedReactant = (Id, Vec<u8>);

pub trait Contract: Serialize + for<'a> Deserialize<'a> + Send + Sync + Clone + std::fmt::Debug + 'static {
    type Init: Serialize + for<'a> Deserialize<'a> + Hash + Send + Sync;
    fn init(init: Self::Init, signer: Name, timestamp: u64) -> Self;

    fn id() -> Id;

    fn reactants() -> Reactants<Self>;
}

pub trait Reactant<C: Contract>: Serialize + for<'a> Deserialize<'a> + std::fmt::Debug + 'static {
    type Ok;
    type Err: std::error::Error;

    fn id() -> Id;

    fn apply(self, model: &mut C, signer: Name, timestamp: u64) -> Result<Self::Ok, Self::Err>;
}

#[derive(Debug)]
pub struct Guard<'a, C>(PhantomData::<fn(&'a ())>, Arc<Option<C>>);
impl<'a, C> std::ops::Deref for Guard<'a, C> {
    type Target = C;
    fn deref(&self) -> &C {self.1.as_ref().as_ref().unwrap()}
}

#[derive(Clone)]
pub struct Instance<C: Contract>{
    id: Id,
    sink: Sink,
    name: Name,
    purser: Purser,
    resolver: Resolver,
    location: Location,
    reactants: Arc<Reactants<C>>,
    confirmed: Arc<ArcSwap<Option<C>>>,//This will only be written to by the instance
    queue: Arc<Mutex<VecDeque<SerializedReactant>>>,
    pending: Arc<ArcSwap<Option<C>>>,
}
impl<C: Contract> std::fmt::Debug for Instance<C> {fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.debug_struct("Instance").field("id", &self.id).field("confirmed", &self.confirmed).field("pending", &self.pending).finish()
}}

impl<C: Contract> Instance<C> {
    fn start(resolver: Resolver, purser: Purser, secret: Secret, location: Location, init: Option<C::Init>) -> Self {
        let id = Id::hash(&location);
        let name = secret.name();
        let cache = Cache::new(format!("{}/{}/{}", name, C::id(), id)).unwrap();
        let secret = secret.derive(&[C::id(), id]);
        let channel = cache.get::<Channel>("channel").unwrap().unwrap_or(Channel::new(location.key));
        let (stream, sink) = channel.start(resolver.clone(), purser.clone(), &secret);
        if let Some(init) = init.as_ref() {
            sink.write_sync(postcard::to_allocvec(&(id, postcard::to_allocvec(init).unwrap())).unwrap());
        }
        let contract = cache.get::<C>("model").unwrap();
        let reactants = Arc::new(C::reactants());
        let confirmed = Arc::new(ArcSwap::from(Arc::new(contract.clone())));
        let queue = Arc::new(Mutex::new(VecDeque::new()));
        let pending = Arc::new(ArcSwap::from(Arc::new(contract.or(init.map(|i| C::init(i, secret.name(), now()))))));
        let instance = Instance{name, sink, purser: purser.clone(), resolver: resolver.clone(), id: Id::hash(&location), location, reactants, confirmed, queue, pending};
        spawn(instance.clone().run(cache, stream));
        instance
    }

    pub fn share(&self, name: Name) {
        spawn(InboxHandler::send(self.purser.clone(), self.resolver.clone(), name, self.location));
    }

    pub fn pending(&self) -> Guard<'_, C> {
        Guard(PhantomData::<fn(&'_ ())>, self.pending.load().clone())
    }

    pub fn confirmed(&self) -> Option<Guard<'_, C>> {
        let arc = self.confirmed.load().clone();
        arc.is_some().then_some(Guard(PhantomData::<fn(&'_ ())>, arc))
    }

    pub fn apply<R: Reactant<C>>(&self, reactant: R) -> Result<R::Ok, R::Err> {
        let id = self.reactants.index::<R>().unwrap_or_else(|| panic!("
            The given reactant was not found in its contract,
            Add it to the contract in Contract::reactants(): {:?}
        ", reactant));
        let bytes = postcard::to_allocvec(&reactant).unwrap();
        self.sink.write_sync(postcard::to_allocvec(&(id, &bytes)).unwrap());

        let mut pending = self.pending.load_full().as_ref().clone().expect("Cannot apply reactant to an uninitialized contract");
        let mut queue = self.queue.blocking_lock();
        queue.push_back((id, bytes));
        let r = reactant.apply(&mut pending, self.name, now())?;
        self.pending.store(Arc::new(Some(pending)));
        Ok(r)
    }

    async fn store(&mut self, confirmed: C, reactant: Option<Id>) {
        let mut pending = confirmed.clone();
        self.confirmed.store(Arc::new(Some(confirmed)));
        let mut queue = self.queue.lock().await;
        if let Some(id) = reactant
        && queue.front().map(|(i, _)| i == &id).unwrap_or_default() {
            queue.pop_front();
        }
        for (id, bytes) in queue.iter() {
            self.reactants.apply(id, bytes, &mut pending, self.name, now());
        }
        self.pending.store(Arc::new(Some(pending)));
    }

    async fn run(mut self, mut cache: Cache, mut stream: Stream) {
        loop {
            let (time, namedata) = stream.read().await;
            if let Some((name, data)) = namedata
            && let Ok((id, bytes)) = postcard::from_bytes::<(Id, Vec<u8>)>(&data) {
                println!("data: {:?}", (id, &bytes));
                match self.confirmed.load_full().as_ref() {
                    None => {
                        if id == self.id && let Ok(init) = postcard::from_bytes(&bytes) {
                            self.store(C::init(init, name, time), None).await;
                        } else {
                            println!("Invalid Contract Init")
                        }
                    },
                    Some(contract) => {
                        let mut contract = contract.clone();
                        if self.reactants.apply(&id, &bytes, &mut contract, name, time) {
                            self.store(contract, Some(id)).await;
                        }
                    }
                }
            }
            cache.insert("channel", stream.channel()).unwrap();
        }
    }
}

#[derive(Clone)]
pub struct Context {
    secret: Secret,
    instances: ArcLock<BTreeMap<Id, BTreeMap<Id, AnyInstance>>>,
    resolver: Resolver,
    purser: Purser,
    tx: MAsyncTx<mpsc::List<Request>>,
}

impl Context {
    pub fn me(&self) -> Name {self.secret.name()}
    pub fn create<C: Contract>(&self, init: C::Init) -> Instance<C> {
        let location = Location::new::<C>(&self.secret, &init);
        self.get::<C>(location, Some(init))
    }


    pub fn list<C: Contract>(&self) -> Vec<Instance<C>> {
        self.instances.load().get(&C::id()).map(|map| map.values().filter_map(|i| {
            let instance = i.downcast_ref::<Instance<C>>().unwrap();
            instance.pending.load().as_ref().as_ref().map(|_| instance.clone())
        }).collect()).unwrap_or_default()
    }

    fn get<C: Contract>(&self, location: Location, init: Option<C::Init>) -> Instance<C> {
        let c_id = C::id();
        let id = Id::hash(&location);
        match self.instances.load().get(&c_id).and_then(|i| i.get(&id)) {
            Some(instance) => instance.downcast_ref::<Instance<C>>().unwrap().clone(),
            None => self.instances.blocking_lock(|a: &ArcSwap<BTreeMap<Id, BTreeMap<Id, AnyInstance>>>| {
                let mut map = a.load_full().as_ref().clone();
                let instance = map.entry(c_id).or_insert_with(|| {
                    self.tx.try_send(Request::Register(C::id(), InstanceBuilder::new::<C>(self.resolver.clone(), self.purser.clone(), self.secret.clone(), self.instances.clone()))).unwrap();
                    BTreeMap::default()
                }).entry(id).or_insert_with(|| {
                    self.tx.try_send(Request::New(location)).unwrap();
                    Arc::new(Box::new(Instance::<C>::start(self.resolver.clone(), self.purser.clone(), self.secret.clone(), location, init)))
                });
                let instance = instance.downcast_ref::<Instance<C>>().unwrap().clone();
                a.store(Arc::new(map));
                instance
            })
        }
    }


}

///Keeps track of my Contracts and their locations for recovery, (Scanning my inbox, creating new
///channels, storing and listening for new instances. Air never touches a contract Init
pub struct Air {
    resolver: Resolver,
    purser: Purser,
    secret: Secret,
    cache: Cache,
    root: Root,
    rx: AsyncRx<mpsc::List<Request>>,
    inbox: InboxHandler,
    futures: FuturesUnordered<PBFut<(Id, Stream, u64, Data)>>,
    contracts: BTreeMap<Id, (Option<InstanceBuilder>, Sink)>,
}

impl Air {
    pub fn start(secret: Secret) -> Context {
        let name = secret.name();
        let cache = Cache::new(format!("./{name}.db")).unwrap();
        let root = cache.get::<Root>("root").unwrap().unwrap_or_default();

        let resolver = Resolver::start();
        let purser = Purser::start(resolver.clone());

        let (tx, rx) = mpsc::build(mpsc::List::new());
        let inbox = root.inbox.start(resolver.clone(), purser.clone(), secret.clone());
        let context = Context{
            secret: secret.clone(),
            instances: ArcLock::new(BTreeMap::new()),
            purser: purser.clone(),
            resolver: resolver.clone(),
            tx,
        };

        spawn(async move {
            let futures = FuturesUnordered::new();
            let contracts = root.contracts.iter().map(|(id, (channel, _))| {
                let (mut stream, sink) = channel.start(resolver.clone(), purser.clone(), &secret);
                let id = *id;
                futures.push(Box::pin(async move {
                    let (time, namedata) = stream.read().await;
                    (id, stream, time, namedata)
                }) as _);
                (id, (None, sink))
            }).collect();
            Air{resolver, purser, secret, cache, root, rx, inbox, futures, contracts}.run().await
        });

        context
    }

    fn contract(&mut self, id: Id) -> &mut (Channel, HashSet<Location>) {
        self.root.contracts.entry(id).or_insert_with(|| {
            let secret = self.secret.derive(&[id]);
            let channel = Channel::new(secret.harden());
            let (mut stream, sink) = channel.start(self.resolver.clone(), self.purser.clone(), &secret);
            self.contracts.insert(id, (None, sink));
            self.futures.push(Box::pin(async move {
                let (time, namedata) = stream.read().await;
                (id, stream, time, namedata)
            }) as _);
            (channel, HashSet::default())
        })
    }

    async fn add(&mut self, location: Location, post: bool) {
        let entry = self.contract(location.contract_id);
        if !entry.1.insert(location) {
            let (_, sink) = self.contracts.get(&location.contract_id).unwrap();
            sink.write(postcard::to_allocvec(&location).unwrap()).await;
            let (receiver, _) = self.contracts.get(&location.contract_id).unwrap();
            if post && let Some(builder) = receiver.as_ref() {
                (builder.0)(location).await;
            }
        }
    }

    async fn run(mut self) {
        loop {
            tokio::select!{
                (_, location) = self.inbox.read() => {
                    self.root.inbox = *self.inbox.inbox();
                    if let Some(location) = location {self.add(location, true).await}
                },
                Some((id, mut stream, _, namedata)) = self.futures.next() => {
                    self.root.contracts.get_mut(&id).unwrap().0 = *stream.channel();

                    if let Some((_, data)) = namedata 
                    && let Ok((key, contract_hash)) = postcard::from_bytes::<(SecretKey, Id)>(&data) {
                        let location = Location{key, contract_id: id, contract_hash};
                        self.add(location, true).await;
                    }

                    self.futures.push(Box::pin(async move {
                        let (time, namedata) = stream.read().await;
                        (id, stream, time, namedata)
                    }) as _);
                },
                Ok(request) = self.rx.recv() => match request {
                    //Register new contracts and new instances???
                    Request::Register(id, builder) => {
                        for location in &self.contract(id).1 { 
                            (builder.0)(*location).await;
                        }
                        self.contracts.get_mut(&id).unwrap().0 = Some(builder);
                    },
                    Request::New(location) => {self.add(location, false).await;}
                },
                else => {}
            }           
            self.cache.insert("root", &self.root).unwrap();
        }
    }
}

pub struct Reactants<C>(BTreeMap<Id, (TypeId, String, ReactantApply<C>)>);
impl<C: Contract> std::fmt::Debug for Reactants<C> {fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.debug_map().entries(self.0.iter().map(|(id, i)| (id, &i.1))).finish()
}}
impl<C: Contract> Default for Reactants<C> {fn default() -> Self {Reactants(BTreeMap::default())}}
impl<C: Contract> Reactants<C> {
    pub fn add<R: Reactant<C>>(mut self) -> Self {
        self.0.insert(R::id(), (TypeId::of::<R>(), std::any::type_name::<R>().to_string(), Box::new(|bytes: &[u8], model: &mut C, signer: Name, timestamp: u64| {
            match postcard::from_bytes::<R>(bytes) {
                Ok(r) => {
                    let mut pending = model.clone();
                    match r.apply(&mut pending, signer, timestamp) {
                        Ok(_) => {
                            *model = pending;
                            true
                        },
                        Err(e) => {
                            println!("Invalid Reactant: {e:?}");
                            false
                        }
                    }
                },
                Err(e) => {
                    println!("Invalid Reactant: {e:?}");
                    false
                }
            }
        })));
        self
    } 

    fn index<R: Reactant<C> + 'static>(&self) -> Option<Id> {
        let ty_id = TypeId::of::<R>();
        self.0.iter().find_map(|(id, (ty, _, _))| (*ty == ty_id).then_some(*id))
    }

    fn apply(&self, id: &Id, bytes: &[u8], model: &mut C, signer: Name, timestamp: u64) -> bool {
        match self.0.get(id) {
            Some((_, _, reactant)) => {reactant(bytes, model, signer, timestamp)},
            None => {println!("No Reactant With Id: {:?}", id); false}
        }
    }
}

struct Cache(Connection);
impl Cache {
    pub fn new<P: AsRef<Path>>(path: P) -> Result<Self, Error> {
        let mut conn = if cfg!(test) {
            Connection::open_with_flags(
                format!("file:mem_{}?mode=memory", Id::hash(&path.as_ref().to_path_buf())), 
                OpenFlags::SQLITE_OPEN_READ_WRITE |
                OpenFlags::SQLITE_OPEN_CREATE |
                OpenFlags::SQLITE_OPEN_URI
            )?
        } else {
            let _ = std::fs::create_dir_all(path.as_ref());
            Connection::open(path)?
        };
        conn.pragma_update(None, "locking_mode", "EXCLUSIVE")?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Exclusive)?;
        tx.execute("CREATE TABLE if not exists Cache(
            key TEXT NOT NULL PRIMARY KEY,
            value BLOB NOT NULL
        );", [])?;
        tx.commit()?;
        Ok(Cache(conn))
    }
    pub fn get<T: for<'a> Deserialize<'a>>(&self, key: &str) -> Result<Option<T>, Error> {
        Ok(self.0.query_row(
            &format!("SELECT value FROM Cache WHERE key='{key}'"),
            [], |r| Ok(postcard::from_bytes(&r.get::<_, Vec<u8>>(0)?).ok()),
        ).optional()?.flatten())
    }

    pub fn insert<T: Serialize>(&mut self, key: &str, value: &T) -> Result<(), Error> {
        self.0.execute(
            &format!("INSERT INTO Cache(key, value) VALUES ('{key}', ?1) ON CONFLICT DO UPDATE SET value=excluded.value;"),
            [postcard::to_allocvec(value).unwrap()],
        )?;
        Ok(())
    }
}

struct InstanceBuilder(Box<dyn Fn(Location) -> PBFut<()> + Send + Sync>);
impl InstanceBuilder {
    pub fn new<C: Contract>(resolver: Resolver, purser: Purser, secret: Secret, instances: ArcLock<BTreeMap<Id, BTreeMap<Id, AnyInstance>>>) -> Self {
        InstanceBuilder(Box::new(move |location: Location| {
            let resolver = resolver.clone();
            let purser = purser.clone();
            let secret = secret.clone();
            let instances = instances.clone();
            Box::pin(async move {
                let c_id = C::id();
                let id = Id::hash(&location);
                if !instances.load().get(&c_id).unwrap().contains_key(&id) {
                    instances.lock(|a: &ArcSwap<BTreeMap<Id, BTreeMap<Id, AnyInstance>>>| {
                        let mut map = a.load_full().as_ref().clone();
                        map.get_mut(&c_id).unwrap().entry(id).or_insert_with(||
                            Arc::new(Box::new(Instance::<C>::start(resolver.clone(), purser.clone(), secret.clone(), location, None)))
                        );
                        a.store(Arc::new(map));
                    }).await;
                }
            })
        }))
    }
}

#[derive(Debug)]
struct ArcLock<T>(Arc<(Mutex<()>, ArcSwap<T>)>);
impl<T> Clone for ArcLock<T> {fn clone(&self) -> Self {Self(self.0.clone())}}
impl<T> ArcLock<T> {

    pub fn new(init: T) -> Self {
        ArcLock(Arc::new((Mutex::new(()), ArcSwap::from(Arc::new(init)))))
    }
    pub async fn lock<R>(&self, callback: impl FnOnce(&ArcSwap<T>) -> R) -> R {
        let _lock = self.0.0.lock().await;
        callback(&self.0.1)
    }

    pub fn blocking_lock<R>(&self, callback: impl FnOnce(&ArcSwap<T>) -> R) -> R {
        let _lock = self.0.0.blocking_lock();
        callback(&self.0.1)
    }

    pub fn load(&self) -> arc_swap::Guard<Arc<T>, DefaultStrategy> {self.0.1.load()}
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
