use crate::names::{Id, Secret, Resolver, Signed, Name, secp256k1::SecretKey};

use crate::{Purser, Channel, Response, Request as StorageRequest};

use std::collections::BTreeMap;
use std::path::{PathBuf, Path};
use std::hash::Hash;
use std::any::TypeId;

use serde::{Serialize, Deserialize};
pub use substance::{Substance, Beaker, into, from};

#[derive(Debug)]
pub enum Error {
    UnregisteredContract(Id),
    InvalidReactant(Id, PathBuf),
    InvalidInstance(String)
}
impl std::error::Error for Error {}
impl std::fmt::Display for Error {fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {write!(f, "{self:?}")}}


pub trait Reactant: Serialize + for<'a> Deserialize<'a> + Hash {
    type Contract: Contract;
    type Error: std::error::Error;

    fn to_vec(&self) -> Vec<u8> {serde_json::to_vec(self).unwrap()}
    fn from_slice(s: &[u8]) -> Result<Self, String> {serde_json::from_slice(s).map_err(|e| e.to_string())}

    fn apply<B: Beaker>(self, path: &Path, signer: &Name, timestamp: u64, substance: &mut B) -> Result<(), Self::Error>;
}

pub trait Contract: Serialize + for<'a> Deserialize<'a> + Hash {
    fn id() -> Id;

    fn init(self, signer: &Name, timestamp: u64) -> Substance;

    fn routes() -> BTreeMap<PathBuf, Reactants>;

    fn to_vec(&self) -> Vec<u8> {serde_json::to_vec(self).unwrap()}
    fn from_slice(s: &[u8]) -> Result<Self, String> {serde_json::from_slice(s).map_err(|e| e.to_string())}
}

type Apply = Box<dyn Fn(&[u8], &Path, &Name, u64, &mut Substance) -> bool + Send + Sync>;

#[derive(Default)]
pub struct Reactants(Vec<(Apply, TypeId, String)>);
impl Reactants {
    pub fn new() -> Self {Self::default()}

    pub fn add<R: Reactant + 'static>(mut self) -> Self{
        if self.index::<R>().is_none() {
            self.0.push((Box::new(|b: &[u8], p: &Path, n: &Name, t: u64, c: &mut Substance|
                match R::from_slice(b).map(|e| e.apply(p, n, t, c)) {
                    Err(s) => {log::warn!("Corrupted Reactant: {s}"); false},
                    Ok(Err(s)) => {log::warn!("Reactant Error: {s}"); false},
                    Ok(Ok(())) => true,
                }
            ), TypeId::of::<R>(), std::any::type_name::<R>().to_string()));
        }
        self
    }

    fn call(&self, index: usize, b: &[u8], p: &Path, s: &Name, t: u64, o: &mut Substance) -> bool {
        match self.0.get(index) {
            Some((e, _, _)) => {e(b, p, s, t, o); true},
            None => false
        }
    }

    fn index<R: Reactant + 'static>(&self) -> Option<usize> {
        let id = TypeId::of::<R>();
        self.0.iter().position(|r| r.1 == id)
    }
}

type Routes = BTreeMap<PathBuf, Reactants>;
type InitFromSlice = Box<dyn Fn(&[u8], &Name, u64) -> Result<(Id, Substance), Error> + Send + Sync>;
type Pending = BTreeMap<u64, Signed<Vec<u8>>>;

#[derive(Serialize, Deserialize, Debug, Hash)]
struct Missive(Id, SecretKey, Vec<u8>); 
#[derive(Serialize, Deserialize, Debug)]
struct Instance(Id, Channel, Substance);

#[derive(Default)]
pub struct Contracts(BTreeMap<Id, (InitFromSlice, Routes)>);
impl Contracts {
    pub fn new() -> Self {Contracts(BTreeMap::new())}
    pub fn add<C: Contract + 'static>(mut self) -> Self {
        self.0.insert(C::id(), (Box::new(|b: &[u8], signer: &Name, timestamp: u64|
            C::from_slice(b).map_err(Error::InvalidInstance).map(|c| (Id::hash(&(signer, &c)), c.init(signer, timestamp)))), C::routes()
        ));
        self
    }

    fn accept(&self, missive: &Signed<Missive>) -> Result<Instance, Error> {
        let c = self.0.get(&missive.as_ref().0).ok_or(Error::UnregisteredContract(missive.as_ref().0))?;
        (c.0)(&missive.as_ref().2, &missive.signer(), missive.datetime()).map(|(hash, s)| 
            Instance(Id::hash(&(&missive.as_ref().1, hash)), Channel::from(missive.as_ref().1), s)
        )
    }
}

enum _Request {
    Create(Missive),
    Share(Id, Id, Name),
    Send(Id, Id, PathBuf, usize, Vec<u8>),
}
pub struct Request(_Request);
#[derive(Clone, Debug)]
pub struct RequestBuilder(Secret, BTreeMap<Id, BTreeMap<PathBuf, Vec<TypeId>>>);
impl RequestBuilder {
    pub fn name(&self) -> Name {self.0.name()}

    pub fn create<C: Contract>(&self, contract: C) -> Result<(Id, Request), Error> {
        let id = C::id();
        if !self.1.contains_key(&id) {Err(Error::UnregisteredContract(id))?}
        let hash = Id::hash(&(&self.0.name(), &contract));
        let key = self.0.derive(&[id, hash]).harden();
        let iid = Id::hash(&(&key, hash));
        Ok((iid, Request(_Request::Create(Missive(id, key, serde_json::to_vec(&contract).unwrap())))))
    }

    pub fn share<C: Contract>(&self, iid: Id, name: Name) -> Result<Request, Error> {
        let id = C::id();
        if !self.1.contains_key(&id) {Err(Error::UnregisteredContract(id))?}
        Ok(Request(_Request::Share(id, iid, name)))
    }

    pub fn send<P: AsRef<Path>, R: Reactant + 'static>(&self, id: Id, path: P, reactant: R) -> Result<Request, Error> {
        let c_id = R::Contract::id();
        let path = path.as_ref().to_path_buf();
        let rid = TypeId::of::<R>();
        let i = self.1.get(&c_id).ok_or(Error::UnregisteredContract(c_id))?.get(&path).and_then(|r| r.iter().position(|r| *r == rid)).ok_or(Error::InvalidReactant(c_id, path.clone()))?;
        let ser = serde_json::to_vec(&reactant).unwrap();
        Ok(Request(_Request::Send(c_id, id, path, i, ser)))
      //Ok(reactant.apply(path.as_ref(), self.name(), now(), &mut beaker.copy()).map(|_|
      //    Request(_Request::Send(c_id, id, path, i, ser))
      //))
    }
}

type I = (Signed<Missive>, Instance);

#[derive(Serialize, Deserialize)]
pub struct Manager {
    secret: Secret,
    root: Channel,
    channels: BTreeMap<Id, (Channel, BTreeMap<Id, I>)>,
    inbox_time: u64,
    #[serde(skip)]
    contracts: Contracts,
}
impl Manager {
    pub fn new(secret: Secret) -> Self {
        let root = secret.derive(&[Id::hash("contracts")]);
        Manager {
            root: Channel::from(root.harden()),
            channels: BTreeMap::default(),
            secret,
            inbox_time: 0,
            contracts: Contracts::default()
        }
    }

    pub fn init(&mut self, contracts: Contracts) {
        contracts.0.keys().for_each(|id| {self.channels.entry(*id).or_insert((Channel::from(self.secret.derive(&[Id::hash("contracts"), *id]).harden()), BTreeMap::new()));});
        self.contracts = contracts;
    }

    pub fn request_builder(&self) -> RequestBuilder {
        RequestBuilder(self.secret.clone(), self.contracts.0.iter().map(|(id, c)|
            (*id, c.1.iter().map(|(p, r)| (p.clone(), r.0.iter().map(|t| t.1).collect())).collect())
        ).collect())
    }

    pub fn get(&self) -> BTreeMap<Id, BTreeMap<Id, Substance>> {
        self.channels.iter().map(|(i, c)| (*i, c.1.iter().map(|(ii, t)| (*ii, t.1.2.clone())).collect())).collect()
    }

    pub async fn tick(&mut self, requests: Option<Request>) {
        let mut pending_events: BTreeMap<(Id, Id), Pending> = BTreeMap::new();
        let mut pending_instances: BTreeMap<Id, Pending> = BTreeMap::new();
        //1. Scan Missives
        if let Response::Inbox(missives) = Purser::send(&mut Resolver, &Name::orange_me(), StorageRequest::Receive(Signed::new(&self.secret, self.inbox_time).unwrap())).await.unwrap() {
            for (m, data) in missives {
                self.inbox_time = self.inbox_time.max(m.as_ref().timestamp);
                if let Ok(missive) = serde_json::from_slice::<Signed<Missive>>(&data)
                && let Some((_, instances)) = self.channels.get_mut(&missive.as_ref().0)
                && let Ok(instance) = self.contracts.accept(&missive) 
                && !instances.contains_key(&instance.0) {
                    instances.insert(instance.0, (missive, instance));
                }
            }
        }
        //2. Handle Inputs
        if let Some(Request(request)) = requests {match request {
            _Request::Create(missive) => {
                let id = missive.0;
                let contract_channel = &mut self.channels.get_mut(&id).unwrap().0;
                let results = contract_channel.send_all(Some(Signed::new(&self.secret, serde_json::to_vec(&Signed::new(&self.secret, missive).unwrap()).unwrap()).unwrap())).await.unwrap();
                pending_instances.entry(id).or_default().extend(results);
            },
            _Request::Share(id, iid, name) => {
                let instances = &mut self.channels.get_mut(&id).unwrap().1;
                let missive = &instances.get_mut(&iid).unwrap().0;
                Purser::send(&mut Resolver, &Name::orange_me(), StorageRequest::Send(name, serde_json::to_vec(missive).unwrap())).await.unwrap();
            },
            _Request::Send(id, iid, path, index, event) => {
                let instances = &mut self.channels.get_mut(&id).unwrap().1;
                let instance = instances.get_mut(&iid).unwrap();

                let results = instance.1.1.send_all(Some(Signed::new(&self.secret, serde_json::to_vec(&(path, index, event)).unwrap()).unwrap())).await.unwrap();
                pending_events.entry((id, iid)).or_default().extend(results);
            }
        }}
        

        //3. Scan for new instances, events
        for (id, (channel, instances)) in &mut self.channels {
            let results = channel.send_all(None).await.unwrap();
            pending_instances.entry(*id).or_default().extend(results);

            instances.extend(pending_instances.remove(id).unwrap().into_values().flat_map(|signed| {
                let me = signed.signer() == self.secret.name();
                let missive = serde_json::from_slice::<Signed<Missive>>(&signed.into_inner()).ok().filter(|_| me).unwrap();//?;
                let instance = self.contracts.accept(&missive).ok().unwrap();//?;
                Some((instance.0, (missive, instance)))
            }));

            for (iid, (_, instance)) in instances {
                let results = instance.1.send_all(None).await.unwrap();
                pending_events.entry((*id, *iid)).or_default().extend(results);

                pending_events.remove(&(*id, *iid)).unwrap().into_iter().for_each(|(t, signed)| {
                    let signer = signed.signer();
                    let (path, index, event) = serde_json::from_slice::<(PathBuf, usize, Vec<u8>)>(&signed.into_inner()).unwrap();
                    let mut substance = instance.2.clone();
                    if let Some(reactants) = &self.contracts.0.get(id).and_then(|c| c.1.get(&path))
                    && reactants.call(index, &event, &path, &signer, t, &mut substance) {
                        instance.2 = substance;
                    } else {panic!("p");}
                });
            }
        }
    }
}
