use crate::names::{Id, Secret, Resolver, Signed, Name, secp256k1::SecretKey, now};

use crate::{Purser, Inbox, InboxHandler, channel, Channel, Response, Request as StorageRequest, Compare};

use std::collections::{HashMap, HashSet};
use std::path::{PathBuf, Path};
use std::hash::Hash;
use std::any::TypeId;
use std::sync::Arc;

use serde::{Serialize, Deserialize};
use crate::substance::{Substance, Beaker, into, from, Offset, Logger};

use crossfire::{MAsyncTx, MAsyncRx, AsyncTx, AsyncRx, mpsc, mpmc, spsc};
use tokio::spawn;

use futures_util::stream::FuturesUnordered;
use futures_util::StreamExt;
use rusqlite::{Connection, OptionalExtension};

use crate::contract::{ErasedContract, ErasedReactant, Reactant, Contract, Cache};

use arc_swap::ArcSwap;
use std::pin::Pin;

const INSTANCES: &str = "INSTANCES";

#[derive(Serialize, Deserialize, Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub struct Location {
    pub key: SecretKey,
    pub contract_id: Id,
    pub contract_hash: Id,
}
impl Location {
    pub fn new<C: Contract>(secret: &Secret, contract: &C) -> Self {
        let c_id = C::id();
        let data = postcard::to_allocvec(&contract).unwrap();
        let hash = Id::hash(&(c_id, &data));
        let secret = secret.derive(&[c_id, hash]);
        let key = secret.harden();
        Location{key, contract_id: c_id, contract_hash: hash}
    }
}

#[derive(Clone, Debug)]
struct PendingReactant(Id, PathBuf, ErasedReactant, Vec<u8>, Name);
impl PendingReactant {
    pub fn apply(&self, pending: &mut Substance) {
        let mut pending = pending.clone();
        let mut offset = Offset::new(Logger::new(pending), self.1.clone());
        if (self.2.apply)(&self.3, &self.1, &self.4, now(), &mut offset) {
            pending = offset.into_inner().0;
        }
    }
}

#[derive(Clone, Debug)]
pub struct Model {
    confirmed: Option<Substance>,
    queued: Vec<PendingReactant>,
    pending: Substance
}
impl Model {
    pub fn from(confirmed: Substance) -> Self {Model{
        confirmed: Some(confirmed.clone()),
        queued: Vec::new(),
        pending: confirmed
    }}

    pub fn new(pending: Substance) -> Self {Model{
        confirmed: None,
        queued: Vec::new(),
        pending
    }}

    pub fn init(&mut self, init: Substance) {
        self.confirmed = Some(init);
        let mut pending = self.confirmed.clone().unwrap();
        for reactant in &self.queued {
            reactant.apply(&mut pending);
        }
        self.pending = pending;
        //Apply queued to confirmed and store in pending
    }

    pub fn get(&self) -> Option<&Substance> {self.confirmed.as_ref()}
    pub fn get_pending(&self) -> &Substance {&self.pending}

    //Upon receiving a confirmed reactant I need to recompute the current pending queue and state
    async fn add(&mut self, reactant: &ErasedReactant, data: &[u8], path: &Path, signer: &Name, time: u64) -> Option<Vec<PathBuf>> {
        let confirmed = self.confirmed.as_ref().expect("Tried to apply confirmed reactant before init").clone();
        let mut offset = Offset::new(Logger::new(confirmed), path.to_path_buf());
        if self.queued.first().map(|f| f.0 == Id::hash(&(path, &data))).unwrap_or(false) {
            self.queued.remove(0);
        }
        let result = if (reactant.apply)(data, path, signer, time, &mut offset) {
            let logger = offset.into_inner();
            self.confirmed = Some(logger.0);
            Some(logger.1)
        } else {None};

        let mut pending = self.confirmed.clone().unwrap();
        for reactant in &self.queued {
            reactant.apply(&mut pending);
        }
        self.pending = pending;

        result
    }

    pub fn add_pending<R: Reactant + 'static>(&mut self, reactant: R, path: &Path, signer: &Name) -> Result<(), R::Error>{
        let pending = self.pending.clone();
        let mut offset = Offset::new(Logger::new(pending), path.to_path_buf());
        let data = postcard::to_allocvec(&reactant).unwrap();
        reactant.apply(path, signer, now(), &mut offset)?;
        self.pending = offset.into_inner().0;
        self.queued.push(PendingReactant(Id::hash(&(path, &data)), path.to_path_buf(), ErasedReactant::erase::<R>(), data, *signer)); 
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct Instance {
    pub secret: Secret,
    pub location: Location,
    pub contract: Arc<ErasedContract>,
    pub updates: MAsyncRx<mpmc::List<PathBuf>>,
    pub model: Arc<ArcSwap<Model>>,
    pub sink: channel::Sink,
}
impl Instance {
    ///Receiving a new instance from another device or Missive will take a while as it waits for
    ///the init message. async?
    pub fn start(resolver: Resolver, purser: Purser, secret: &Secret, contract: Arc<ErasedContract>, location: Location) -> Result<Self, rusqlite::Error> {
        println!("Instance Started");
        let id = Id::hash(&location);
        let mut cache = Cache::new(format!("{INSTANCES}/{}.db", id)).unwrap();
        let (channel, substance) = match cache.get::<(Channel, Option<Substance>)>("instance")? {
            //If I have a substance I have passed the init phase
            Some((channel, substance)) => (channel, substance.map(Model::from)),
            None => (Channel::new(location.key), None) 
        };
        let initalized = substance.is_some();
        let model = Arc::new(ArcSwap::from(Arc::new(substance.unwrap_or(Model::new(Substance::default())))));
        let (stream, sink) = channel.start(resolver, purser, &secret).split();
        let (tx, updates) = mpmc::build(mpmc::List::new());
        let instance = Instance{secret: secret.clone(), sink, location, contract, model, updates};
        spawn(instance.clone().run(initalized, cache, stream, tx));
        Ok(instance)
    }

    pub async fn receive(resolver: Resolver, purser: Purser, secret: Secret, contract: Arc<ErasedContract>, location: Location, instances: Arc<ArcSwap<im::HashMap<Id, Instance>>>) {
        let instance = Self::start(resolver, purser, &secret, contract, location).unwrap();
        if instance.model.load().confirmed.is_none() {
            instance.updates.recv().await.unwrap();
        }
        instances.rcu(|instances| {
            let mut instances = instances.as_ref().clone();
            instances.entry(Id::hash(&instance.location)).or_insert(instance.clone());
            instances
        });
    }

    //Never called if the instance was already local, Could exist though
    //If the instance database was locked returns None, This means another thread created this
    //instance and its ready to go, check the instances list again
    pub fn new<C: Contract + 'static>(resolver: Resolver, purser: Purser, secret: &Secret, contract: C) -> Option<Self> {
        let location = Location::new(secret, &contract);
        let id = Id::hash(&location);
        let _ = std::fs::create_dir(INSTANCES);
        match Cache::new(format!("{INSTANCES}/{}.db", id)) {
            Ok(cache) => {
                let secret = secret.derive(&[C::id(), id]);
                let (stream, mut sink) = Channel::new(location.key).start(resolver, purser, &secret).split();
                sink.write_sync(postcard::to_allocvec(&contract).unwrap());
                let (tx, updates) = mpmc::build(mpmc::List::new());
                let instance = Instance{
                    secret: secret.clone(),
                    location,
                    contract: Arc::new(ErasedContract::erase::<C>()),
                    updates,
                    model: Arc::new(ArcSwap::from(Arc::new(Model::new(contract.init(&secret.name(), now()))))),
                    sink
                };
                spawn(instance.clone().run(false, cache, stream, tx));
                Some(instance)
            },
            Err(_) => {
                //Assume it was because the database was locked
                None
            }
        }
    }

    pub fn send<P: AsRef<Path>, R: Reactant + 'static>(self, path: P, index: usize, reactant: R) -> Result<(), R::Error> {
        let path = path.as_ref().to_path_buf();
        let old = self.model.load_full().clone();
        let mut new = old.as_ref().clone();
        let data = postcard::to_allocvec(&reactant).unwrap();
        let data = postcard::to_allocvec(&(path.to_path_buf(), index as u64, data)).unwrap();
        new.add_pending(reactant, &path, &self.secret.name())?;
        self.model.compare_and_swap(&old, new.into());
        self.sink.write_sync(data);
        Ok(())
    }
    
    //Shut down if updates is dropped, 
    async fn run(self, mut initialized: bool, mut cache: Cache, mut stream: channel::Stream, updates: MAsyncTx<mpmc::List<PathBuf>>) {
        loop {
            if let (time, Some((signer, data))) = stream.read().await {
                if initialized {
                    if let Ok((path, index, data)) = postcard::from_bytes::<(PathBuf, u64, Vec<u8>)>(&data) {
                        if let Some(reactant) = self.contract.get(&path, index as usize) {
                            let mut model: Model = self.model.load_full().as_ref().clone();
                            if let Some(u) = model.add(&reactant, &data, &path, &signer, time).await {
                                self.model.swap(model.into());
                                for update in u {
                                    updates.send(update).await.unwrap();
                                }
                            }
                        }
                    }
                } else {
                    if self.location.contract_hash == Id::hash(&(self.location.contract_id, &data)) {
                        match (self.contract.init)(&data, &signer, time) {
                            Err(e) => println!("Invalid Contract Init: {:?}", e),
                            Ok(s) => {
                                initialized = true;
                                let mut model: Model = self.model.load_full().as_ref().clone();
                                model.init(s);
                                updates.send(PathBuf::from("/")).await.unwrap();
                                self.model.swap(model.into());
                            }
                        }
                    } else {println!("Not my INIT");}
                }
            }
            cache.insert("instance", &(stream.channel(), &self.model.load_full().confirmed)).unwrap();
        }
    }
}
