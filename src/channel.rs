use crate::names::{Secret, Signed, Name, Id, Resolver, Error};
use crate::names::secp256k1::{Signed as KeySigned, SecretKey, PublicKey, Encrypted as KeyEncrypted};
use crate::storage::{Request, Response};

use serde::{Serialize, Deserialize};

use std::collections::VecDeque;
use std::hash::Hash;
use std::fmt::Debug;

#[derive(Serialize, Deserialize, Hash, Debug, Clone, Eq, PartialEq)]
pub struct Location {
    pub server: Name,
    pub path: Vec<Id>,
    pub key: SecretKey,
}

pub struct Midstate(SecretKey, PublicKey, Option<Id>);

#[derive(Debug)]
pub enum Event<I> {
    Pending,//Check front of queue for the message
    Confirmed(I, u64, Name),
    Empty(u64),
}

pub trait Change {
    fn merge(self, other: Self) -> Self;
}

pub trait Distributable: Default {
    type Message: Serialize + for<'a> Deserialize<'a> + Clone + Debug + Hash;
    type Change: Change;

    fn apply(&mut self, me: &Name, queue: &VecDeque<Self::Message>, message: Event<Self::Message>) -> Self::Change;
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Channel<D: Distributable> {
    distributed: D,
    queue: VecDeque<D::Message>,
    location: Location,
    timestamp: u64,
    index: u64,
    me: Name,
}

impl<D: Distributable> std::ops::Deref for Channel<D> {
    type Target = D; fn deref(&self) -> &D {&self.distributed}
}

impl<D: Distributable> Channel<D> {
    pub fn new(me: Name, location: Location) -> Self {Channel{
        distributed: D::default(), queue: VecDeque::new(),
        location, timestamp: 0, index: 0, me
    }}

    pub fn location(&self) -> &Location {&self.location}

    pub fn apply(&mut self, message: D::Message) -> D::Change {
        self.queue.push_back(message);
        self.distributed.apply(&self.me, &self.queue, Event::Pending)
    }

    pub fn request(&self, secret: &Secret) -> Result<(Midstate, Request), Error> {
        let secret = secret.set_path(&self.location.path)?;
        let key = self.location.key.derive(&[Id::hash(&self.location.server)]).derive(&[Id::hash(&self.index)]);
        let public = key.public_key();

        Ok(match self.queue.front() {
            Some(outgoing) => {
                let signed = postcard::to_allocvec(&Signed::new(&secret, &outgoing)).unwrap();
                let encrypted = postcard::to_allocvec(&public.encrypt(signed)).unwrap();
                (Midstate(key, public, Some(Id::hash(&encrypted))), Request::Create(KeySigned::new(&key, encrypted)))
            },
            None => (Midstate(key, public, None), Request::Read(public, true))
        })
    }

    pub async fn response<R: Resolver>(&mut self, resolver: &mut R, midstate: &Midstate, response: Response) -> Option<D::Change> {
        let (signature, time, hash, data) = match (midstate.2, response) {
            (Some(hash), Response::Created(signature, time)) => (signature, time, hash, None),
            (_, Response::Read(signature, time, Some(data))) => (signature, time, Id::hash(&data.1), Some(data)),
            (None, Response::Read(signature, time, None)) => (signature, time, Id::MIN, None),
            _ => {return None;}
        };
        let identity = resolver.resolve(self.location.server, Some(time)).await;
        if signature.verify(&identity, &[], Id::hash(&(midstate.1, time, hash))).is_ok() {
            self.index += 1;
            if time > self.timestamp {
                self.timestamp = time;
                return match (hash, data) {
                    (Id::MIN, None) => Some(self.distributed.apply(&self.me, &self.queue, Event::Empty(time+1))),
                    (_, None) => {
                        let msg = self.queue.pop_front().unwrap();
                        let change = self.distributed.apply(&self.me, &self.queue, Event::Confirmed(msg, time, self.me));
                        //TODO: This second event is a hack to let the object know its reached the head of the channel
                        Some(change.merge(self.distributed.apply(&self.me, &self.queue, Event::Empty(time+1))))
                        
                    },
                    (hash, Some((key_sig, payload))) if midstate.1.verify(&key_sig, hash).is_ok() => {
                        if let Some(signed) = postcard::from_bytes::<KeyEncrypted>(&payload).ok().and_then(|e|
                            midstate.0.decrypt(e).ok().and_then(|d|
                                postcard::from_bytes::<Signed<D::Message>>(&d).ok()
                            )
                        ) {
                            let identity = resolver.resolve(signed.signer, Some(time)).await;
                            if signed.verify(&identity, &self.location.path).is_ok() {
                                Some(self.distributed.apply(&self.me, &self.queue, Event::Confirmed(signed.payload, time, signed.signer)))
                            } else {None}
                        } else {None}
                    }
                    _ => None
                }
            }
        }
        None
    }
}















//  use std::collections::HashMap;
//  use std::hash::Hash;
//  use std::fmt::Debug;

//  use crate::names::{now, Name, Signature, Id, Secret, Signed, Resolver};
//  use crate::names::secp256k1::{Signature as KeySignature, Signed as KeySigned, PublicKey};

//  use serde::{Serialize, Deserialize};
//  use rusqlite::{Connection, params, OptionalExtension};

//  use crossfire::{MAsyncTx, AsyncTx, AsyncRx, mpsc, spsc};
//  use tokio::spawn;

//  pub type Time = (Compare, u64);

//  #[derive(Serialize, Deserialize, Debug, Clone, Hash, PartialEq, Eq, Copy)]
//  pub enum Compare {Greater, GreaterOrEqual, Equal, LesserOrEqual, Lesser}
//  impl std::fmt::Display for Compare {fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {write!(f, "{}", match self {
//      Self::Greater => ">".to_string(),
//      Self::GreaterOrEqual => ">=".to_string(),
//      Self::Equal => "=".to_string(),
//      Self::LesserOrEqual => "<=".to_string(),
//      Self::Lesser => "<".to_string(),
//  })}}

//  #[derive(Serialize, Deserialize, Debug, Clone, Hash, PartialEq, Eq)]
//  pub enum Request{
//      Create(KeySigned<Vec<u8>>),
//      Read(PublicKey, bool),//Subscribe

//      Send(Name, Vec<u8>),
//      Receive(Signed<Time>),
//  }

//  impl Request {
//      pub fn max_responses(&self) -> usize {match self {
//          Self::Read(_, true) => 2,
//          _ => 1
//      }}
//  }

//  #[derive(Serialize, Deserialize, Debug, Clone, Hash, PartialEq, Eq)]
//  pub enum Response {
//      Create(Signature, u64),
//      Read(Signature, u64, Option<(KeySignature, Vec<u8>)>),
//      
//      Inbox(Vec<(Signature, u64, Vec<u8>)>),

//      InvalidRequest(String),
//      InvalidSignature(String),
//  }

//  type Responder = AsyncTx<spsc::Array<Response>>;

//  #[derive(Clone)]
//  pub struct Storage(MAsyncTx<mpsc::List<(Request, Responder)>>);
//  impl Storage {
//      pub fn start(secret: &Secret) -> Self {
//          let (tx, rx) = mpsc::build(mpsc::List::new());
//          let resolver = Resolver::start();
//          spawn(Self::run(resolver, secret.clone(), rx));
//          Storage(tx)
//      }

//      pub async fn request(&mut self, request: Request) -> AsyncRx<spsc::Array<Response>> {
//          let (stx, srx) = spsc::build(spsc::Array::new(request.max_responses()));
//          let _ = self.0.send((request, stx)).await;
//          srx
//      }

//      async fn run(resolver: Resolver, secret: Secret, rx: AsyncRx<mpsc::List<(Request, Responder)>>) {
//          let mut subscriptions = HashMap::<PublicKey, Vec<Responder>>::new();
//          let mut subscriptions_inbox = HashMap::<Name, Vec<Responder>>::new();
//          let connection = Connection::open("STORAGE.db").unwrap();
//          connection.execute("CREATE TABLE if not exists private(
//              key TEXT NOT NULL UNIQUE,
//              key_signature BLOB NOT NULL,
//              signature BLOB NOT NULL,
//              timestamp BLOB NOT NULL,
//              payload BLOB NOT NULL
//          );", []).unwrap();

//          connection.execute("CREATE TABLE if not exists inbox(
//              recipient TEXT NOT NULL,
//              timestamp INT NOT NULL,
//              signature BLOB NOT NULL,
//              payload BLOB NOT NULL
//          );", []).unwrap();

//          while let Ok((request, responder)) = rx.recv().await {
//              println!("request: {:?}", request);
//              match request {
//                  Request::Create(signed) => {
//                      let hash = Id::hash(&signed.payload);
//                      let timestamp = now();
//                      let signature = secret.sign(Id::hash(&(signed.key, timestamp, hash)));
//                      match signed.verify() {
//                          Ok(()) => {
//                              let result = connection.query_row(
//                                  "INSERT INTO private(key, signature, timestamp, key_signature, payload)
//                                   VALUES (?1, ?2, ?3, ?4, ?5) ON CONFLICT DO UPDATE SET key=?1
//                                   RETURNING signature, key_signature, timestamp, payload;",
//                                  params![
//                                      postcard::to_allocvec(&signed.key).unwrap(),
//                                      postcard::to_allocvec(&signature).unwrap(),
//                                      postcard::to_allocvec(&timestamp).unwrap(),
//                                      postcard::to_allocvec(&signed.signature).unwrap(),
//                                      signed.payload
//                                  ],
//                                  |row| Ok((
//                                      postcard::from_bytes::<Signature>(&row.get::<_, Vec<u8>>("signature")?).unwrap(),
//                                      postcard::from_bytes::<u64>(&row.get::<_, Vec<u8>>("timestamp")?).unwrap(),
//                                      postcard::from_bytes::<KeySignature>(&row.get::<_, Vec<u8>>("key_signature")?).unwrap(),
//                                      row.get::<_, Vec<u8>>("payload")?
//                                  ))
//                              ).unwrap();
//                              if signature == result.0 {
//                                  if let Some(responders) = subscriptions.remove(&signed.key) {
//                                      let response = Response::Read(result.0.clone(), result.1, Some((result.2, result.3)));
//                                      for responder in responders {
//                                          let _ = responder.send(response.clone()).await;
//                                      }
//                                  }
//                                  let _ = responder.send(Response::Create(result.0, result.1)).await;
//                              } else {
//                                  let _ = responder.send(Response::Read(result.0, result.1, Some((result.2, result.3)))).await;
//                              }
//                          },
//                          Err(e) => {let _ = responder.send(Response::InvalidSignature(e.to_string())).await;},
//                      }
//                  },
//                  Request::Read(key, subscribe) => {
//                      if let Some(read) = connection.query_row(
//                          "SELECT signature, timestamp, key_signature, payload FROM private WHERE key=?1",
//                          [postcard::to_allocvec(&key).unwrap()], |row| Ok(Response::Read(
//                              postcard::from_bytes::<Signature>(&row.get::<_, Vec<u8>>("signature")?).unwrap(),
//                              postcard::from_bytes::<u64>(&row.get::<_, Vec<u8>>("timestamp")?).unwrap(),
//                              Some((
//                                  postcard::from_bytes::<KeySignature>(&row.get::<_, Vec<u8>>("key_signature")?).unwrap(),
//                                  row.get::<_, Vec<u8>>("payload")?
//                              ))
//                          ))
//                      ).optional().unwrap() {
//                          let _ = responder.send(read).await;
//                      } else {
//                          let timestamp = now();
//                          let id = Id::hash(&(key, timestamp, Id::MIN));
//                          let _ = responder.send(Response::Read(secret.sign(id), timestamp, None)).await;
//                          if subscribe {
//                              subscriptions.entry(key).or_default().push(responder);
//                          }
//                      }
//                  },
//                  Request::Send(recipient, payload) => {
//                      let timestamp = now();
//                      let signature = secret.sign(Id::hash(&(recipient, timestamp, &payload)));
//                      connection.execute(
//                          "INSERT INTO inbox(recipient, timestamp, signature, payload) VALUES (?1, ?2, ?3, ?4)",
//                          params![
//                              recipient.to_string(),
//                              timestamp as isize,
//                              serde_json::to_vec(&signature).unwrap(),
//                              payload,
//                          ],
//                      ).unwrap();
//                      let _ = responder.send(Response::Create(signature.clone(), timestamp)).await;
//                      if let Some(responders) = subscriptions_inbox.remove(&recipient) {
//                          let response = Response::Inbox(vec![(signature, timestamp, payload)]);
//                          for responder in responders {
//                              let _ = responder.send(response.clone()).await;
//                          }
//                      }
//                  },
//                  Request::Receive(signed) => {
//                      let identity = resolver.resolve(signed.signer, None).await;
//                      match signed.verify(&identity, &[]) {
//                          Ok(()) => {
//                              let recipient = signed.signer;
//                              let (ordering, timestamp) = signed.payload;
//                              let query = format!("SELECT signature, timestamp, payload FROM inbox WHERE recipient='{recipient}' AND timestamp{ordering}'{timestamp}'");
//                              let results = connection.prepare(&query).unwrap().query_map(
//                                  [], |r| Ok((
//                                      serde_json::from_slice::<Signature>(&r.get::<_, Vec<u8>>(0)?).unwrap(),
//                                      r.get::<_, isize>(1)? as u64,
//                                      r.get::<_, Vec<u8>>(2)?,
//                                  ))
//                              ).unwrap().collect::<Result<Vec<_>, rusqlite::Error>>().unwrap();
//                              if results.is_empty() {
//                                  subscriptions_inbox.entry(signed.signer).or_default().push(responder);
//                              } else {
//                                  let _ = responder.send(Response::Inbox(results)).await;
//                              }
//                          },
//                          Err(e) => {let _ = responder.send(Response::InvalidSignature(e.to_string())).await;}
//                      }
//                  }
//              }
//          }
//      }
//  }

//  #[cfg(test)]
//  mod test {
//      use super::*;
//      use crate::names::{Resolver, secp256k1::SecretKey};

//      #[tokio::test]
//      async fn create() {
//          let server = Secret::new();
//          let server_name = server.name();
//          let resolver = Resolver::start();
//          let identity = resolver.resolve(server_name, None).await;
//          let mut storage = Storage::start(&server);

//          let file_key = SecretKey::new();
//          let content = b"my file contents".to_vec();

//          if let Response::Create(signature, timestamp) = storage.request(Request::Create(KeySigned::new(&file_key, content.clone()))).await.recv().await.unwrap() {
//              signature.verify(&identity, &[], Id::hash(&(file_key.public_key(), timestamp, Id::hash(&content)))).unwrap();
//          } else {panic!("Unexpected Response");}
//      }

//      #[tokio::test]
//      async fn inbox() {
//          let server = Secret::new();
//          let server_name = server.name();
//          let resolver = Resolver::start();
//          let identity = resolver.resolve(server_name, None).await;
//          let mut storage = Storage::start(&server);

//          let bob = Secret::new();
//          let bob_name = bob.name();

//          let content = b"my file contents".to_vec();

//          let timestamp = if let Response::Create(signature, timestamp) = storage.request(Request::Send(bob_name, content.clone())).await.recv().await.unwrap() {
//              signature.verify(&identity, &[], Id::hash(&(bob_name, timestamp, &content))).unwrap();
//              timestamp
//          } else {panic!("Unexpected Response");};

//          let request = storage.request(Request::Receive(Signed::new(&bob, (Compare::Greater, 0)))).await;
//          if let Response::Inbox(received) = request.recv().await.unwrap() {
//              for (signature, _, content) in received {
//                  signature.verify(&identity, &[], Id::hash(&(bob_name, timestamp, &content))).unwrap();
//              }
//          } else {panic!("Unexpected Response");}
//      }































//  use crate::names::{secp256k1::{Signed as KeySigned, SecretKey, Encrypted as KeyEncrypted}, Encrypted, Signature, Secret, Signed, Name, Id, now};
//  use crate::storage::{Compare, Request, Response};
//  use crate::{Air, Store};

//  use std::marker::{PhantomData, Unpin};
//  use std::collections::VecDeque;
//  use std::fmt::Debug;
//  use std::hash::Hash;
//  use std::sync::Arc;

//  use crossfire::{MTx, MAsyncTx, AsyncTx, AsyncRx, mpsc, spsc};
//  use postage::broadcast::{channel, Sender, Receiver};
//  use postage::prelude::{Sink, Stream};
//  use serde::{Serialize, Deserialize};

//  use crate::ams::{Ams, Ref, Update};

//  pub const CHANNEL: &str = "CHANNEL";

//  //Objects must be serilaizable for caching which must be driven by the Distributed struct
//  pub trait Distributable: Serialize + for<'a> Deserialize<'a> + Default + Clone + Send + Sync + 'static {
//      type Event: Serialize + for<'a> Deserialize<'a> + Unpin + Debug + Hash + Send + Sync + 'static;

//      ///If any modifications were made its important to return Something to indicate that the event
//      ///should be stored and propigated
//      fn on_event(&mut self, event: Item<Self::Event>);
//  }

//  #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
//  pub enum Item<M> {
//      Restored,
//      Pending(M, Name),//You created a new outgoing message
//      ConfirmedPending(u64),//The first message in your queue was confirmed
//      NewConfirmed(M, Name, u64),//You received a new message from someone else
//      EmptyResponse(u64)
//  }

//  pub struct Ref<'a, T>(MutexGuard<'a, T>);
//  impl Deref for Ref<'a, T> {
//      type Target = T;
//      fn deref(&self) -> &T {self.0}
//  }

//  #[derive(Serialize, Deserialize, Hash, Debug, Clone, Eq, PartialEq)]
//  pub struct Location {
//      pub server: Name,
//      pub path: Vec<Id>,
//      pub key: SecretKey,
//  }
//  impl Location {
//      pub fn new(server: Name, path: Vec<Id>, key: SecretKey) -> Self {Location{server, path, key}}
//      pub fn share(&self, air: Air, name: Name) {
//          let bytes = postcard::to_allocvec(&self).unwrap();
//          air.clone().spawn(async move {
//              let identity = air.resolver.resolve(name, None).await;
//              let home = *identity.servers().first().unwrap();
//              let conn = air.purser.connect(home).await.unwrap();
//              conn.send(Request::Send(name, postcard::to_allocvec(&identity.encrypt(&[], bytes)).unwrap())).await;
//          });
//      }
//  }

//  //The Distributed Object will not leave this process, The Shared<D> can be used througout the
//  //processes

//  ///Shared is a special type of AMS that clears updates on load since its assumed you are
//  ///proccessing everything seen. And that the Updates contain all the neccessary information to stay
//  ///up to date or to know what is needed to be read
//  #[derive(Clone)]
//  pub struct Distributed<D: Distributable> {
//      air: Air,
//      secret: Secret,
//      location: Location,
//      writer: MTx<mpsc::List<Vec<u8>>>,//This works but does not allow updates to the outgoing Queue while it has not yet been revealed(IE offline)
//      distributable: Arc<Mutex<D>>,
//  }
//  impl<D: Distributable> Distributed<D> {
//      pub fn apply(&mut self, msg: D::Event) {
//          let mut locked = self.distributable.lock().unwrap();
//          let serialized = postcard::to_allocvec(&Signed::new(&self.secret, &msg)).unwrap();
//          locked.on_event(&self.air, Item::Pending(msg));
//          self.writer.try_send(serialized).unwrap();
//      }

//      pub fn location(&self) -> &Location {&self.location}
//      pub fn get(&self) -> Ref<'_, D> {Ref(self.distributable.lock().unwrap())}
//      pub fn share(&self, name: Name) {self.location.share(self.air.clone(), name)}

//      pub fn new(air: Air, location: Location) -> Self {
//          let id = Id::hash(&location);
//          let (distributed, mut queue, mut index, mut timestamp) = air.get::<(Arc<Mutex<D>>, VecDeque<Vec<u8>>, u64, u64)>(&id.to_string()).unwrap_or_default();

//          let key = location.key;
//          let secret = air.secret.derive(&location.path);

//          let d = distributed.clone();
//          let l = location.clone();
//          let a = air.clone();

//          let mut apply = async move |air: &Air, event: Item<S::Event>| {
//              let mut d = distributed.lock();
//              d.on_event(air, event)
//          };

//          let (writer, rx): (MTx<_>, AsyncRx<_>) = mpsc::build(mpsc::List::new());

//          let start = now();
//          let key = location.key.derive(&[Id::hash(&location.server)]);

//          a.spawn(async move { 
//              apply(&air, Item::Restored).await;
//              //TODO: Shared must work while offline
//              let connection = air.purser.connect(location.server).await.unwrap();
//              loop {
//                  let key = key.derive(&[Id::hash(&index)]);
//                  let public = key.public_key();
//                  let (created_hash, request) = match queue.front() {
//                      Some(file) => {
//                          let encrypted = postcard::to_allocvec(&public.encrypt(file.clone())).unwrap();
//                          (Some(Id::hash(&encrypted)), Request::Create(KeySigned::new(&key, encrypted)))
//                      },
//                      None => (None, Request::Read(public, true))
//                  };
//                  let mut request = connection.send(request).await;

//                  let mut verify_outer = async |signature: Signature, time: u64, hash: Id| {
//                      let identity = air.resolver.resolve(location.server, Some(time)).await;
//                      if signature.verify(&identity, &[], Id::hash(&(public, time, hash))).is_ok() {
//                          index += 1;
//                          if time > timestamp {
//                              timestamp = time;
//                              true
//                          } else {println!("Bad Time"); false}
//                      } else {panic!("Bad Air Server");}
//                  };
//                  
//                  ///Right now I will get stuck subscribed to a message and not sending off one of my
//                  ///pending
//                  loop { tokio::select!{
//                       Ok(serialized) = rx.recv() =>  {
//                          queue.push_back(serialized);
//                          //If I am Subscribed (At head and not creating) and I get a new pending send it off
//                          if created_hash.is_none() {break;}
//                          //In the future I will also send off the reactant here instead of
//                          //waiting to read everything else first
//                      },
//                      response = request.recv() => match (created_hash, response) {
//                          (Some(hash), Response::Create(signature, time)) => {
//                              verify_outer(signature, time, hash).await;
//                              //TODO: When I can read and write independently I can remove this hack
//                              apply(&air, Item::EmptyResponse(time-1)).await;
//                              apply(&air, Item::ConfirmedPending(time)).await;
//                              break
//                          },
//                          (created_hash, Response::Read(signature, time, data)) => {
//                              if created_hash.is_some() && data.is_none() {panic!("Bad Air Server");}
//                              let hash = data.as_ref().map(|(_, payload)| Id::hash(payload)).unwrap_or(Id::MIN);
//                              if verify_outer(signature, time, hash).await {
//                                  if !head && (data.is_none() || time > start) {
//                                      head = true;
//                                      apply(&air, Item::EmptyResponse(time)).await;
//                                      //Subscribing, If I have pending switch to creating it
//                                      if !queue.is_empty() {break;}
//                                  }
//                                  if let Some((key_sig, payload)) = data {
//                                      if let Some(signed) = postcard::from_bytes::<KeyEncrypted>(&payload).ok().and_then(|e|
//                                          key.decrypt(e).ok().and_then(|d| postcard::from_bytes::<Signed<S::Event>>(&d).ok())
//                                      ) {
//                                          let identity = air.resolver.resolve(signed.signer, Some(time)).await;
//                                          if signed.verify(&identity, &location.path).is_ok() {
//                                              apply(&air, Item::NewConfirmed(signed.payload, signed.signer, time)).await;
//                                          } else {println!("Bad Signature");}
//                                      } else {println!("Bad Encryption/Serialization");}
//                                  }
//                              }
//                              break
//                          },
//                          _ => panic!("Bad Air Server"),
//                      }
//                  }}
//                  air.set(&id.to_string(), &(&shared, &queue, index, timestamp));
//              }
//          });
//          Shared{air: a, distributed: d, secret, writer, location: l}
//      }
//  }

//  pub enum Item {
//      Created(u64),
//      Received(Name, u64, Vec<u8>),
//      EmptyResponse(u64),
//      Garbage,
//  }

//  pub struct Midstate(Option<Id>);

//  #[derive(Serialize, Deserilaize)]
//  pub struct Channel {
//      location: Location,
//      timestamp: u64,
//      index: u64,
//  }

//  impl Channel {
//      pub fn new(location: Location) -> Self {Channel{location, timestamp: 0, index: 0}}
//      pub fn request(&self, secret: &Secret, outgoing: Option<Vec<u8>>) -> (Midstate, Request) {
//          let key = self.location.key.derive(&[Id::hash(&self.location.server)]).derive(&[Id::hash(&self.index)]);
//          let public = key.public_key();

//          match outgoing {
//              Some(outgoing) => {
//                  //TODO: verify inefficent
//                  let signed = postcard::to_allocvec(&Signed::new(&secret, &outgoing)).unwrap();
//                  let encrypted = postcard::to_allocvec(&public.encrypt(signed)).unwrap();
//                  (Midstate(Some(Id::hash(&encrypted))), Request::Create(KeySigned::new(&key, encrypted)))
//              },
//              None => (Midstate(None), Request::Read(public, true))
//          }
//      }

//      //Returns a vector of Item to allow for the case where when writing I also know I have no
//      //reads and emit an EmptyResponse(time-1) as a hack
//      pub fn response(&mut self, resolver: &mut Resolver, midstate: Midstate, response: Response) -> Vec<Item> {
//          let (signature, time, hash, data) = match (midstate.0, response) {
//              (Some(hash), Response::Create(signature, time)) => (signature, time, hash, None),
//              (_, Response::Read(signature, time, Some(data))) => (signature, time, Id::hash(&data.1), Some(data)),
//              (None, Response::Read(signature, time, None)) => (signature, time, Id::MIN, None),
//              _ => {return vec![Item::Garbage];}
//          };
//          let identity = resolver.resolve(self.location.server, Some(time)).await;
//          match signature.verify(&identity, &[], Id::hash(&(public, time, hash))) {
//              Ok(_) => {
//                  index += 1;
//                  match time > timestamp {
//                      true => {
//                          timestamp = time;
//                          match (hash, data) {
//                              (Id::MIN, None) => vec![Item::EmptyResponse(time)],
//                              (_, None) => vec![Item::EmptyResponse(time-1), Event::Created(time)],
//                              (hash, Some((key_sig, payload))) => match public.verify(key_sig, hash) {
//                                  Ok(_) => {
//                                      match postcard::from_bytes::<KeyEncrypted>(&payload).ok().and_then(|e|
//                                          key.decrypt(e).ok().and_then(|d|
//                                              postcard::from_bytes::<Signed<Vec<u8>>>(&d).ok()
//                                          )
//                                      ) {
//                                          Some(signed) => {
//                                              let identity = resolver.resolve(signed.signer, Some(time)).await;
//                                              match signed.verify(&identity, &self.location.path) {
//                                                  Ok(_) => vec![Item::Received(signed.signer, time, signed.payload)],
//                                                  Err(_) => vec![Item::Garbage]
//                                              }
//                                          },
//                                          None => vec![Item::Garbage]
//                                      }
//                                  },
//                                  Err(_) => vec![Item::Garbage]
//                              }
//                          }
//                      },
//                      false => vec![Item::Garbage]
//                  }
//              },
//              Err(_) => vec![Item::Garbage]
//          }
//      }
//  }



//  #[cfg(test)]
//  mod test {
//      use super::*;

//    //pub struct Doc {
//    //    alpha: String,
//    //    bravo: String,
//    //    cursor: HashMap<Name, (bool, usize)>,
//    //    pending: VecDeque<(Name, char)>
//    //}
//    //impl Sharable for Doc {
//    //    type Event = (Option<bool>, Option<usize>, Option<char>);
//    //    type Update = (bool, bool);

//    //    fn on_event(&mut self, air: &Air, event: Item<Self::Event>) -> Option<Self::Update> {

//    //    }
//    //}


//      #[tokio::test]
//      async fn test() {
//        //let bob = Secret::new();
//        //let alice = Secret::new();

//        //let id = Id::random();
//        //let location = Location::new(vec![id], bob.derive(&[id]).harden());

//        //let shared = Shared::<Data>::new(location);

//      }
//  }








//  //  #[derive(Serialize, Deserialize, PartialEq, Eq, Clone, Copy, Debug, Default)]
//  //  pub struct Channel {
//  //      //pub servers: Vec<Name>,
//  //      pub key: SecretKey,
//  //      pub index: u64,
//  //      pub timestamp: u64,
//  //  }

//  //  impl Channel {
//  //      pub fn new(key: SecretKey) -> Self {Channel{key, index: 0, timestamp: 0}}

//  //      ///It is assumed that the channels path is equal to the path of the secret
//  //      ///Its up to you to ensure the secret is at the correct path for this channel
//  //      pub fn start(mut self, air: Air, secret: Secret) -> (Stream, Sink) {
//  //          //pull previous state from air
//  //          //I need to provide a handler call back to receive the event on stream
//  //          //and cache the channel at the same time I cache the handler
//  //          //A channel cannot simply provide me with updates becasue moving the Channel forward is
//  //          //critical to the state of the object listening to the updates


//  //          let secret = secret.derive(&[Id::hash(CHANNEL)]);
//  //          let (write, rx): (MAsyncTx<_>, AsyncRx<_>) = mpsc::build(mpsc::List::new());
//  //          let (tx, read): (AsyncTx<_>, AsyncRx<_>) = spsc::build(spsc::List::new());

//  //          let channel = self;
//  //          air.handle.spawn(async move {
//  //              let mut head = false;
//  //              let server = Name::orange_me();
//  //              let key = self.key.derive(&[Id::hash(&server)]);
//  //              let connection = air.purser.connect(server).await.unwrap();

//  //              let mut request: Option<(Vec<u8>, Vec<u8>, Id)> = None;
//  //              loop {
//  //                  let key = key.derive(&[Id::hash(&self.index)]);
//  //                  let public = key.public_key();
//  //                  match &mut request {
//  //                      Some(_) => {},
//  //                      none => {*none = rx.try_recv().ok().map(|tuple: (Id, Vec<u8>)|{
//  //                          (tuple.1.clone(), postcard::to_allocvec(&Signed::new(&secret, tuple.1)).unwrap(), tuple.0)
//  //                      });}
//  //                  }

//  //                  if let Some((signature, time, key_sig, payload)) = match request.as_ref() {
//  //                      Some((_, data, _)) => {
//  //                          let encrypted = postcard::to_allocvec(&public.encrypt(data.clone())).unwrap();
//  //                          let hash = Id::hash(&encrypted);
//  //                          let response = connection.send(Request::Create(KeySigned::new(&key, encrypted))).await.recv().await;
//  //                          match response{
//  //                              Response::Create(signature, time) => {
//  //                                  let identity = air.resolver.resolve(server, Some(time)).await;
//  //                                  if signature.verify(&identity, &[], Id::hash(&(public, time, hash))).is_ok() 
//  //                                  && self.timestamp < time {
//  //                                      self.timestamp = time;
//  //                                      self.index += 1;
//  //                                      tx.send((self, request.take().map(|(d, _, rid)| Item::Data(secret.name(), d, Some(rid))).expect("Bad Air Server"))).await.unwrap()
//  //                                  } else {panic!("Bad Air Server");}
//  //                                  None
//  //                              },
//  //                              Response::Read(signature, time, Some((key_sig, payload))) => Some((signature, time, key_sig, payload)),
//  //                              _ => {panic!("Bad Air Server")}
//  //                          }
//  //                      },
//  //                      None => {
//  //                          let mut subscription = connection.clone().send(Request::Read(public, true)).await;
//  //                          loop {tokio::select! {
//  //                              Response::Read(signature, time, data) = subscription.recv() => {
//  //                                  if let Some((key_sig, payload)) = data {
//  //                                      break Some((signature, time, key_sig, payload));
//  //                                  } else if !head {
//  //                                      let identity = air.resolver.resolve(server, Some(time)).await;
//  //                                      if signature.verify(&identity, &[], Id::hash(&(public, time, Id::MIN))).is_err() {
//  //                                          panic!("Bad Air Server");
//  //                                      }
//  //                                      head = true;
//  //                                      tx.send((self, Item::Head)).await.unwrap();
//  //                                  }
//  //                              },
//  //                              Ok((rid, d)) = rx.recv() => {
//  //                                  request = Some((d.clone(), postcard::to_allocvec(&Signed::new(&secret, d)).unwrap(), rid));
//  //                                  break None;
//  //                              }
//  //                              else => {panic!("Bad Air Server")}
//  //                          }}
//  //                      }
//  //                  } {
//  //                      self.index += 1;
//  //                      let hash = Id::hash(&payload);
//  //                      let identity = air.resolver.resolve(server, Some(time)).await;
//  //                      if signature.verify(&identity, &[], Id::hash(&(public, time, hash))).is_ok()
//  //                      && key_sig.verify(&public, hash).is_ok() {
//  //                          let result = if time > self.timestamp {
//  //                              self.timestamp = time;
//  //                              if let Some(signed) = postcard::from_bytes::<KeyEncrypted>(&payload).ok().and_then(|e| key.decrypt(e).ok().and_then(|d| postcard::from_bytes::<Signed<Vec<u8>>>(&d).ok())) {
//  //                                  let identity = air.resolver.resolve(signed.signer, Some(time)).await;
//  //                                  if signed.verify(&identity, secret.path()).is_ok() {
//  //                                      Some((signed.signer, signed.payload))
//  //                                  } else {println!("bad signature"); None}
//  //                              } else {println!("bad encryption/serialization"); None}
//  //                          } else {println!("bad time"); None};
//  //                          tx.send((self, result.map(|(a, b)| Item::Data(a, b, None)).unwrap_or(Event::Garbage))).await.unwrap();
//  //                      } else {panic!("Bad Air Server");}
//  //                  }
//  //              }
//  //          });
//  //          (Stream(channel, read), Sink(write))
//  //      }
//  //  }

//  //  #[derive(Debug)]
//  //  pub struct InboxHandler(Inbox, AsyncRx<spsc::List<(u64, Option<Vec<u8>>)>>);
//  //  impl InboxHandler {
//  //      pub fn inbox(&self) -> &Inbox {&self.0}

//  //      pub async fn read(&mut self) -> (u64, Option<Vec<u8>>) {
//  //          let (time, data) = self.1.recv().await.unwrap();
//  //          self.0.0 = time;
//  //          (time, data)
//  //      }

//  //      pub fn send(air: Air, name: Name, location: Vec<u8>) {
//  //          air.handle.spawn(async move {
//  //              let identity = air.resolver.resolve(name, None).await;
//  //              let home = *identity.servers().first().unwrap();
//  //              let conn = air.purser.connect(home).await.unwrap();
//  //              conn.send(Request::Send(name, postcard::to_allocvec(&identity.encrypt(&[], location)).unwrap())).await;
//  //          });
//  //      }
//  //  }

//  //  #[derive(Serialize, Deserialize, Clone, Copy, Debug, Default)]
//  //  pub struct Inbox(u64);
//  //  impl Inbox {
//  //      pub fn start(mut self, air: Air) -> InboxHandler {
//  //          let (tx, rx): (AsyncTx<_>, _) = spsc::build(spsc::List::new());

//  //          air.handle.spawn(async move { loop {
//  //              let identity = air.resolver.resolve(air.name, None).await;
//  //              let home = *identity.servers().first().unwrap();
//  //              let conn = air.purser.connect(home).await.unwrap();
//  //              match conn.send(Request::Receive(Signed::new(&air.secret, (Compare::Greater, self.0)))).await.recv().await {
//  //                  Response::Inbox(received) => {
//  //                      let home_identity = air.resolver.resolve(home, None).await;
//  //                      for (signature, timestamp, data) in received {
//  //                          if signature.verify(&home_identity, &[], Id::hash(&(air.name, timestamp, &data))).is_ok() && timestamp > self.0 {
//  //                              self.0 = timestamp;
//  //                              let data = postcard::from_bytes::<Encrypted>(&data).ok().and_then(|d| air.secret.decrypt(d).ok());
//  //                              tx.send((timestamp, data)).await.unwrap();
//  //                          } else {panic!("Bad Air Server");}
//  //                      }
//  //                  },
//  //                  response => {panic!("Bad Air Server: {response:?}");}
//  //              }
//  //          }});
//  //          InboxHandler(self, rx)
//  //      }
//  //  }

//  //  #[cfg(test)]
//  //  mod test {
//  //      use super::*;

//  //      #[test]
//  //      fn channel() {
//  //          let secret = Secret::new();
//  //          let key = secret.harden();
//  //          let name = secret.name();

//  //          let air = crate::Air::new(secret.clone());

//  //          let (mut stream, sink) = Channel::new(key).start(air.clone(), secret);

//  //          air.handle.block_on(async {
//  //              let content = b"hello".to_vec();
//  //              let rid = sink.write(content.clone()).await;
//  //              let (timestamp, data) = stream.read().await;
//  //              assert_eq!(stream.channel(), &Channel{key, index: 1, timestamp});
//  //              assert_eq!(data, Item::Data(name, content.clone(), Some(rid)));

//  //              let content2 = b"goodbye".to_vec();
//  //              let rid = sink.write(content2.clone()).await;
//  //              let (timestamp2, data2) = stream.read().await;
//  //              assert_eq!(stream.channel(), &Channel{key, index: 2, timestamp: timestamp2});
//  //              assert_eq!(data2, Item::Data(name, content2.clone(), Some(rid)));

//  //              let write = tokio::spawn(async move {
//  //                  tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
//  //                  sink.write(b"late".to_vec()).await
//  //              });

//  //              let (_, data) = stream.read().await;
//  //              assert_eq!(data, Item::Head);

//  //              let rid = write.await.unwrap();

//  //              let (_, data) = stream.read().await;
//  //              assert_eq!(data, Item::Data(name, b"late".to_vec(), Some(rid)));
//  //          });
//  //      }
//  //  }
