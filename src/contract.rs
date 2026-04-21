use crate::names::{Id, Secret, Name, Signed, Resolver, now};
use crate::names::secp256k1::{SecretKey};
use crate::{Purser, Response, Channel};

use std::collections::BTreeMap;
use std::path::{PathBuf, Path};
use std::hash::Hash;
use std::ops::Deref;
use std::pin::Pin;
use std::any::TypeId;
use std::sync::Arc;
use std::str::FromStr;

use serde::{Serialize, Deserialize};
use rusqlite::Connection;
pub use substance::{Substance, Beaker, into, from, Offset};

use tokio::time::{interval, Duration};

pub trait Reactant: Serialize + for<'a> Deserialize<'a> + Hash {
    type Contract: Contract;
    type Error: std::error::Error;

    fn index<P: AsRef<Path>>(path: P) -> Option<usize> where Self: 'static {
        Self::Contract::routes().get(&path.as_ref().to_path_buf()).and_then(|rs| rs.index::<Self>())
    }

    fn to_vec(&self) -> Vec<u8> {serde_json::to_vec(self).unwrap()}
    fn from_slice(s: &[u8]) -> Result<Self, String> {serde_json::from_slice(s).map_err(|e| e.to_string())}

    fn apply<B: Beaker>(self, path: &Path, signer: Name, timestamp: u64, substance: &mut B) -> Result<(), Self::Error>;
}

pub trait Contract: Serialize + for<'a> Deserialize<'a> + Hash {
    fn id() -> Id;

    fn init(self) -> Substance;

    fn routes() -> BTreeMap<PathBuf, Reactants>;

    fn to_vec(&self) -> Vec<u8> {serde_json::to_vec(self).unwrap()}
    fn from_slice(s: &[u8]) -> Result<Self, String> {serde_json::from_slice(s).map_err(|e| e.to_string())}
}

enum Request {
    Create(Id, Vec<u8>),
    Share(Id, Id, Name),
    Send(Id, Id, PathBuf, usize, Vec<u8>),
    //Get(Id, Id, PathBuf)
}

//  impl Request {
//      fn create<C: Contract>(secret: &Secret, contract: C) -> (Id, Self) {
//          (
//              Id::hash(&secret.derive(&[C::id(), Id::hash(&contract)]).unwrap().harden()),
//              Request::Create(C::id(), serde_json::to_vec(&contract).unwrap())
//          )
//      }

//      fn share<C: Contract>(id: Id, name: Name) -> Request {Request::Share(C::id(), id, name)}

//      fn send<P: AsRef<Path>, R: Reactant + 'static, B: Beaker>(secret: &Secret, path: P, reactant: R, beaker: &B) -> Option<Result<Self, R::Error>> {
//          let path = path.as_ref().to_path_buf();
//          R::index(&path).map(|i| {
//              let id = Id::hash(&reactant);
//              let ser = serde_json::to_vec(&reactant).unwrap();
//              reactant.apply(path.as_ref(), secret.name(), now(), &mut beaker.copy())?;
//              Ok(Request::Send(R::Contract::id(), id, path, i, ser))
//          })
//      }
//  }

type Erased = Box<dyn Fn(&[u8], &Path, Name, u64, &mut Offset<Substance>) + Send + Sync>;

#[derive(Default)]
pub struct Reactants(Vec<(Erased, TypeId, String)>);
impl Reactants {
    pub fn new() -> Self {Self::default()}

    pub fn add<R: Reactant + 'static>(&mut self) {
        if self.index::<R>().is_none() {
            self.0.push((Box::new(|b: &[u8], p: &Path, n: Name, t: u64, c: &mut Offset<Substance>|
                match serde_json::from_slice::<R>(b).map(|e| e.apply(p, n, t, c)) {
                    Err(s) => log::warn!("Corrupted Reactant: {s}"),
                    Ok(Err(s)) => log::warn!("Reactant Error: {s}"),
                    Ok(Ok(())) => {},
                }
            ), TypeId::of::<R>(), std::any::type_name::<R>().to_string()));
        }
    }

    pub fn index<R: Reactant + 'static>(&self) -> Option<usize> {
        let id = TypeId::of::<R>(); self.0.iter().position(|r| r.1 == id)
    }
}



//  #[derive(Debug)]
//  pub enum Error<E> {
//      InvalidEvent,
//      ManagerClosed,
//      Event(E),
//  }
//  impl<E: std::error::Error> std::error::Error for Error<E> {}
//  impl<E: std::error::Error> std::fmt::Display for Error<E> {
//      fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {write!(f, "{:?}", self)}
//  }
//  impl<E: std::error::Error> From<E> for Error<E> {fn from(error: E) -> Self {Self::Event(error)}}


//  pub type Events = Vec<Erased>;






//  type Routes = Box<dyn Fn() -> BTreeMap<PathBuf, Vec<Erased>>>;



//  #[derive(Default, Debug)]
//  pub struct Contracts(BTreeMap<Id, (TypeId, BTreeMap<PathBuf, Vec<Erased>>)>);
//  impl Contracts {
//      pub fn new() -> Self {Contracts(BTreeMap::new())}
//      pub fn add<C: Contract + 'static>(mut self) -> Self {
//          self.0.insert(C::id(), (TypeId::of::<C>(), C::routes()));
//          self
//      }
//  }

//  //  #[derive(Clone, Debug)]
//  //  pub struct Instance(Id, TypeId, Id, PathBuf);
//  //  impl Instance {pub fn new(contract: Id, ty_id: TypeId, channel: Id) -> Self {Instance(contract, ty_id, channel, PathBuf::from(format!("{contract}/{channel}")))}}
//  //  impl Deref for Instance { type Target = Id; fn deref(&self) -> &Id {&self.2} }
//  //  impl AsRef<Path> for Instance {fn as_ref(&self) -> &Path {&self.3}}

//  #[derive(Debug)]
//  pub struct Remote {
//      output: Output<Value>,
//      tx: Tx<Array<_Request>>,
//  }
//  impl Deref for Remote {
//      type Target = Value;
//      fn deref(&self) -> &Value {self.output.output_buffer()}
//  }

//  impl Remote {
//      pub fn new<B: Beaker + Send + 'static>(beaker: B, secret: Secret, mut contracts: Contracts) -> Result<Self, B::Error> {
//          let value = beaker.query("values")?.unwrap_or(Value::Map(contracts.0.keys().map(|id| (id.to_string(), Value::map())).collect()));
//          let (mut input, output) = triple_buffer::triple_buffer(&value);

//          let (tx, mut rx) = bounded_blocking(100);
//          let mut channels = beaker.query("channels")?.ok().and_then(|f| from(f).ok()).unwrap_or(
//              Channels(Channel::from(secret.derive(&[Id::hash("$channel")]).unwrap().harden()), BTreeMap::new(), 0)
//          );

//          let mut task = Task{beaker, secret, channels, contracts, input, value, rx};
//          tokio::task::spawn(async move {task.run().await.unwrap()});

//          Ok(Remote{output, tx})
//      }

//      ///Will return None if the manager is closed
//      pub fn create<C: Contract>(&mut self, contract: C) -> Option<PathBuf> {
//          let channel = Channel::default();
//          let channel_id = channel.id();
//          let c_id = C::id();
//          self.tx.send(_Request::New(c_id, channel, contract.init())).ok()?;
//          Some(PathBuf::from(format!("{c_id}/{channel_id}")))
//      }

//      pub fn send<P: AsRef<Path>, E: Event + 'static>(&self, path: P, event: E) -> Result<(), Error<E::Error>> {
//          //TODO: Optionally Attempt to eval Event and return any possible error prior to sending it
//          let ty_id = TypeId::of::<E>();
//          let mut components = path.as_ref().components();
//          let id = components.next().and_then(|id| Id::from_str(&id.as_os_str().to_string_lossy()).ok()).ok_or(Error::InvalidEvent)?;
//          let iid = components.next().and_then(|id| Id::from_str(&id.as_os_str().to_string_lossy()).ok()).ok_or(Error::InvalidEvent)?;
//          let path = components.as_path().to_path_buf();

//          self.tx.send(_Request::Send(id, iid, path, ty_id, serde_json::to_vec(&event).unwrap())).map_err(|_| Error::ManagerClosed)?;
//          Ok(())
//      }

//      pub fn share(&self, id: Id, name: Name) {}
//  }

//  #[derive(Serialize, Deserialize)]
//  struct Channels(Channel, BTreeMap<Id, (Channel, BTreeMap<Id, Channel>)>, u64);


//  struct Task<B> {
//      beaker: B,
//      secret: Secret,
//      channels: Channels,
//      contracts: Contracts,
//      input: Input<Value>,
//      value: Value,
//      rx: Rx<Array<_Request>>
//  }

//  impl<B: Beaker> Task<B> {
//      ///I can turn this into a run function that responsds to channel results and incomming requests
//      ///and poll the channels as fast as possible?
//      pub async fn run(&mut self) -> Result<(), B::Error> {
//          loop {
//              let mut pending_events: BTreeMap<(Id, Id), BTreeMap<u64, Signed<Vec<u8>>>> = BTreeMap::new();
//              let mut pending_instances: BTreeMap<Id, BTreeMap<u64, Signed<Vec<u8>>>> = BTreeMap::new();
//              //1. Scan Missives
//              if let Response::Inbox(missives) = Purser::send(&mut Resolver, &Name::orange_me(), Request::Receive(Signed::new(&self.secret, self.channels.2).unwrap())).await.unwrap() {
//                  for (m, data) in missives {
//                      self.channels.2 = self.channels.2.max(m.as_ref().timestamp);
//                      if let Ok((id, key)) = serde_json::from_slice::<(Id, SecretKey)>(&data)
//                      && let Some((_, instances)) = self.channels.1.get_mut(&id) {
//                          let channel = Channel::from(key);
//                          instances.insert(channel.id(), channel);
//                      }
//                  }
//              }
//              //2. Handle Inputs
//              while let Ok(request) = self.rx.try_recv() {match request {
//                  _Request::New(id, channel, init) => {
//                      let (contract_channel, instances) = self.channels.1.get_mut(&id).unwrap();
//                      let results = contract_channel.send_all(Some(Signed::new(&self.secret, serde_json::to_vec(&channel).unwrap()).unwrap())).await.unwrap();
//                      pending_instances.entry(id).or_default().extend(results);
//                  },
//                  _Request::Share(id, iid, name) => {
//                      let (contract_channel, instances) = self.channels.1.get_mut(&id).unwrap();
//                      let instance = instances.get_mut(&iid).unwrap();
//                      Purser::send(&mut Resolver, &Name::orange_me(), Request::Send(name, serde_json::to_vec(&(id, instance.key)).unwrap())).await.unwrap();
//                  },
//                  _Request::Send(id, iid, path, ty_id, event) => {
//                      let (contract_channel, instances) = self.channels.1.get_mut(&id).unwrap();
//                      let instance = instances.get_mut(&iid).unwrap();

//                      let (index, _) = self.contracts.0.get(&id).unwrap().1.get(&path).unwrap().iter().enumerate().find(|(i, e)| e.1 == ty_id).unwrap();
//                      let results = instance.send_all(Some(Signed::new(&self.secret, serde_json::to_vec(&(path, index, event)).unwrap()).unwrap())).await.unwrap();
//                      pending_events.entry((id, iid)).or_default().extend(results);
//                  }
//              }}
//              

//              //3. Scan for new instances, events
//              for (id, (channel, instances)) in &mut self.channels.1 {
//                  let results = channel.send_all(None).await.unwrap();
//                  pending_instances.entry(*id).or_default().extend(results);

//                  instances.extend(pending_instances.remove(id).unwrap().into_values().flat_map(|signed| {
//                      let me = signed.signer() == self.secret.name();
//                      serde_json::from_slice::<Channel>(&signed.into_inner()).ok().filter(|_| me).map(|c| (c.id(), c))
//                  }));

//                  for (iid, instance) in instances {
//                      let results = instance.send_all(None).await.unwrap();
//                      pending_events.entry((*id, *iid)).or_default().extend(results);

//                      pending_events.remove(&(*id, *iid)).unwrap().into_iter().for_each(|(t, signed)| {
//                          let signer = signed.signer();
//                          if let Ok((path, index, event)) = serde_json::from_slice(&signed.into_inner()) {
//                              let mut offset = Offset::new(&mut self.value, PathBuf::from(&format!("{id}/{iid}")));
//                              if let Some(erased) = self.contracts.0.get(id).unwrap().1.get(path).and_then(|e| e.get::<usize>(index)) {
//                                  let erased: &Erased = erased;
//                                  (*erased.0)(event, path, signer, t, &mut offset)
//                              }
//                          }
//                      });

//                  }
//              }

//              //TODO: These need to happen in the same atomic transaction
//              self.input.write(self.value.clone());
//              self.beaker.insert("value", into(&self.value).unwrap())?.unwrap();
//              self.beaker.insert("channels", into(&self.channels).unwrap())?.unwrap();
//          }
//      }
//  }

//  #[macro_export]
//  macro_rules! events {
//      ($($item:ty),* $(,)?) => {{
//          vec![$($crate::air::Erased::new::<$item>()),*]
//      }};
//  }



//  #[cfg(test)]
//  mod test {
//      use super::*;

//      use tokio::time::{sleep, interval, Duration};
//      use std::convert::Infallible;

//      #[derive(Serialize, Deserialize)]
//      pub struct Send(String);
//      impl Send { pub fn new(body: &str) -> Self { Send(body.to_string())}}
//      impl Event for Send {
//          type Error = Infallible;
//        //fn serialize(&self) -> Vec<u8> {serde_json::to_vec(self).unwrap()}
//        //fn deserialize(b: &[u8]) -> Option<Self> {serde_json::from_slice(b).ok()}

//          fn eval<B: Beaker>(self, path: &Path, signer: Name, timestamp: u64, beaker: &mut B) -> Result<(), EventError<B::Error, Self::Error>> {
//              beaker.insert("-", into(&format!("{}: {}", signer, self.0)).unwrap())?;
//              Ok(())
//          }
//      }

//      #[derive(Hash, PartialEq)]
//      pub struct Room;
//      impl Contract for Room {
//          fn id() -> Id {Id::hash("Room")}

//          fn init(self) -> Value {Value::Seq(vec![])}

//          fn routes() -> BTreeMap<PathBuf, Events> {
//              BTreeMap::from([
//                  (PathBuf::from("/"), events![Send])
//              ])
//          }
//      }

//      #[tokio::test]
//      async fn test() {
//          let bob = Secret::new();
//          let c = Connection::open("file:bob?mode=memory&cache=shared").unwrap();

//          let mut r = Remote::new(c, bob, Contracts::new().add::<Room>()).unwrap();

//          let room = r.create(Room).unwrap();
//          r.send(room, Send::new("Hello")).unwrap();
//          r.send(room, Send::new("Goodbye")).unwrap();

//          sleep(Duration::from_millis(20)).await;

//          assert_eq!(r.query(room).unwrap(), Ok(Value::Seq(vec![
//              Value::Field(Primitive::String("Hello".to_string())),
//              Value::Field(Primitive::String("Goodbye".to_string()))
//          ])));
//      }
//  }
