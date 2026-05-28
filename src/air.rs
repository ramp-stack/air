use crate::names::{Id, Secret, Resolver, Signed, Name, secp256k1::SecretKey, now};

use crate::{Purser, Inbox, InboxHandler, channel, Channel, Response, Request as StorageRequest, Compare};

use std::collections::{HashMap, HashSet, BTreeMap};
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

use arc_swap::ArcSwap;
use std::pin::Pin;

use crate::contract::{ErasedContract, ErasedReactant, Reactant, Contract, Contracts, Error, Cache};
use crate::instance::{Location, Instance};

type PBFut<T> = Pin<Box<dyn Future<Output = T> + Send>>;

#[derive(Serialize, Deserialize, Debug)]
struct Root {
    secret: Secret,
    //root: Channel, I can keep track of my created contracts with this channel in the future
    inbox: Inbox,
    contracts: BTreeMap<Id, (Channel, HashSet<Location>)>,
}

#[derive(Clone, Debug)]
enum Request {
    Share(Name, Location),
}

#[derive(Clone, Debug)]
pub struct Air {
    secret: Secret,
    resolver: Resolver,
    purser: Purser,
    sender: MAsyncTx<mpsc::List<Request>>,
    instances: HashMap<Id, (channel::Sink, Arc<ErasedContract>, Arc<ArcSwap<im::HashMap<Id, Instance>>>)>,
}

impl Air {
    pub fn me(&self) -> Name {self.secret.name()}
    pub fn list<C: Contract>(&self) -> Result<Vec<Id>, Error> {
        let id = C::id();
        Ok(self.instances.get(&id).ok_or(Error::UnregisteredContract(id))?.2.load().keys().copied().collect())
    }

    pub fn get(&self, id: &Id) -> Result<Option<Substance>, Error> {
        self.instances.values().find_map(|(_, _, arc)| arc.load().get(&id).map(|i| i.model.load().get().cloned())).ok_or(Error::MissingInstance(*id))
    }


    pub fn get_pending(&self, id: &Id) -> Result<Substance, Error> {
        self.instances.values().find_map(|(_, _, arc)| arc.load().get(&id).map(|i| i.model.load().get_pending().clone())).ok_or(Error::MissingInstance(*id))
    }

    pub fn create<C: Contract + 'static>(&self, contract: C) -> Result<Id, Error> {
        let c_id = C::id();
        let location = Location::new(&self.secret, &contract);
        let id = Id::hash(&location);

        let (sink, arc_contract, instances) = self.instances.get(&c_id).ok_or(Error::UnregisteredContract(c_id))?;
        if !instances.load().contains_key(&id) {
            match Instance::new(self.resolver.clone(), self.purser.clone(), &self.secret, contract) {
                Some(instance) => {
                    sink.write_sync(postcard::to_allocvec(&instance.location).unwrap());
                    instances.rcu(|instances| {
                        let mut instances = instances.as_ref().clone();
                        instances.entry(id).or_insert(instance.clone());
                        instances
                });
                },
                None if instances.load().contains_key(&id) => {},
                _ => {panic!("Db locked and no running instance");}
            }
        }

        Ok(id)
    }

    pub fn share(&self, id: Id, name: Name) -> Result<(), Error> {
        let location = self.instances.values().find_map(|(_, _, arc)| arc.load().get(&id).map(|i| i.location.clone())).ok_or(Error::MissingInstance(id))?;
        self.sender.try_send(Request::Share(name, location)).unwrap();
        Ok(())
    }

    ///Always test against pending state then send to instance.
    pub fn send<P: AsRef<Path>, R: Reactant + 'static>(&self, id: Id, path: P, reactant: R) -> Result<Result<(), R::Error>, Error> {
        let instance = self.instances.values().find_map(|(_, _, arc)| arc.load().get(&id).cloned()).ok_or(Error::MissingInstance(id))?;
        let index = instance.contract.index::<R>(path.as_ref()).ok_or(Error::InvalidReactant)?;
        Ok(instance.send(path, index, reactant))
    }

    pub fn start(resolver: Resolver, purser: Purser, contracts: Contracts) -> Result<Self, rusqlite::Error> {
        let mut cache = Cache::new("./AIR.db")?;
        let mut root = cache.get::<Root>("root")?.unwrap_or_else(|| Root{
            secret: Secret::new(),
            //root: Channel::from(key.harden()),
            inbox: Inbox::default(),
            contracts: BTreeMap::new()
        });

        let (instances, streams) = contracts.0.into_iter().map(|(c_id, c)| {
            let contract_secret = root.secret.derive(&[c_id]);
            let (channel, locations) = root.contracts.entry(c_id).or_insert((Channel::new(contract_secret.harden()), HashSet::new()));
            let (stream, sink) = channel.start(resolver.clone(), purser.clone(), &contract_secret).split();
            let c = Arc::new(c);
            let instances = locations.iter().map(|location| {
                let id = Id::hash(&location);
                Ok((id, Instance::start(resolver.clone(), purser.clone(), &contract_secret.derive(&[id]), c.clone(), location.clone())?))
            }).collect::<Result<im::HashMap<Id, Instance>, rusqlite::Error>>()?;
            let instances = Arc::new(ArcSwap::from(Arc::new(instances)));
            Ok(((c_id, (sink, c, instances)), (c_id, stream)))
        }).collect::<Result<(HashMap<Id, _>, HashMap<Id, _>), rusqlite::Error>>()?;

        let (tx, rx) = mpsc::build(mpsc::List::new());

        let inbox = root.inbox.start(resolver.clone(), purser.clone(), root.secret.clone());

        let air = Air{
            secret: root.secret.clone(),
            resolver,
            purser,
            sender: tx,
            instances
        };

        spawn(Self::run(cache, root, inbox, streams, air.clone(), rx));
        Ok(air)
    }

    async fn run(mut cache: Cache, mut root: Root, mut inbox: InboxHandler, contracts: HashMap<Id, channel::Stream>, mut air: Air, requests: AsyncRx<mpsc::List<Request>>) {
        let me = root.secret.name();
        let mut contract_channels: FuturesUnordered<PBFut<(Id, channel::Stream, u64, Option<(Name, Vec<u8>)>)>> = FuturesUnordered::new();
        for (id, mut stream) in contracts {
            contract_channels.push(Box::pin(async move {
                let (time, namedata) = stream.read().await;
                (id, stream, time, namedata)
            }) as _);
        }
        loop {
            tokio::select!{
                (time, location) = inbox.read() => {
                    root.inbox = *inbox.inbox();
                    if let Some(location) = location {
                        if let Some((sink, _, _)) = air.instances.get_mut(&location.contract_id) {
                            sink.write(postcard::to_allocvec(&(location.key, location.contract_hash)).unwrap()).await;
                        }
                    }
                },
                Some((id, mut stream, timestamp, namedata)) = contract_channels.next() => {
                    let (channel, locations) = root.contracts.get_mut(&id).unwrap();
                    *channel = *stream.channel();

                    if let Some((name, data)) = namedata {
                        if let Ok((key, contract_hash)) = postcard::from_bytes::<(SecretKey, Id)>(&data) {
                            let location = Location{key, contract_id: id, contract_hash};
                            locations.insert(location);
                            let id = Id::hash(&location);

                            let (_, contract, instances) = air.instances.get(&location.contract_id).unwrap();
                            if !instances.load().contains_key(&id) {
                                spawn(Instance::receive(air.resolver.clone(), air.purser.clone(), root.secret.derive(&[location.contract_id, id]), contract.clone(), location, instances.clone()));
                            }
                        }
                    }

                    contract_channels.push(Box::pin(async move {
                        let (time, namedata) = stream.read().await;
                        (id, stream, time, namedata)
                    }) as _);
                },
                Ok(request) = requests.recv() => match request {
                    Request::Share(name, location) => {
                        InboxHandler::send(&air.purser, &mut air.resolver, name, location).await;
                    }
                    //Air thread has too keep track of outgoing pending and on receiving a new reactant apply all
                    //the outgoing pending to the new current confirmed state
                },
                else => {}
            }

            cache.insert("root", &root).unwrap();
        }
    }
}
