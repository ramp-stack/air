use crate::names::{Signature, Secret, Signed, Name, Id, now, Resolver, Error};
use crate::names::secp256k1::{Signed as KeySigned, PublicKey, Signature as KeySignature};

use serde::{Serialize, Deserialize};

use std::collections::{HashMap, HashSet};
use std::hash::Hash;
use std::fmt::Debug;

pub type Time = (Compare, u64);

#[derive(Serialize, Deserialize, Debug, Clone, Hash, PartialEq, Eq, Copy)]
pub enum Compare {Greater, GreaterOrEqual, Equal, LesserOrEqual, Lesser}

#[derive(Serialize, Deserialize, Debug, Clone, Hash, PartialEq, Eq)]
pub enum Request{
    Create(KeySigned<Vec<u8>>),
    Send(Name, Vec<u8>),

    Read(PublicKey, bool),
    Receive(Signed<Time>, bool),
}

pub enum DBRequest {
    FileRead(PublicKey),
    FileWrite(PublicKey, Signature, u64, KeySignature, Vec<u8>),
    InboxRead(Name, Time),
    InboxWrite(Name, Signature, u64, Vec<u8>)
}

#[derive(Debug)]
pub enum Midstate<I> {
    Creating(I, Signature, u64, KeySigned<Vec<u8>>),
    Sending(I, Name, Signature, u64, Vec<u8>),
    Read(I, PublicKey, u64, bool),
    Receive(I, Signed<Time>, bool)
}
#[derive(Debug)]
pub enum DBResponse {
    File(Option<(Signature, u64, KeySignature, Vec<u8>)>),
    InboxRead(Vec<(Signature, u64, Vec<u8>)>),
    InboxWritten
}

#[derive(Serialize, Deserialize, Debug, Clone, Hash, PartialEq, Eq)]
pub enum Response {
    Created(Signature, u64),
    Read(Signature, u64, Option<(KeySignature, Vec<u8>)>),

    Sent(Signature, u64),
    Inbox(Vec<(Signature, u64, Vec<u8>)>),

    InvalidSignature,
}

#[derive(Default)]
pub struct Storage<I: Eq + Hash>(HashMap<PublicKey, HashSet<I>>, HashMap<Name, HashMap<Time, HashSet<I>>>);
impl<I: Copy + Debug + Eq + Hash> Storage<I> {
    pub async fn request<R: Resolver>(&self, resolver: &mut R, secret: &Secret, id: I, request: Request) -> Result<(Midstate<I>, DBRequest), Error> {Ok(match request {
        Request::Create(signed) => {
            signed.verify()?;
            let hash = Id::hash(&signed.payload);
            let timestamp = now();
            let signature = secret.sign(Id::hash(&(signed.key, timestamp, hash)));
            (Midstate::Creating(id, signature.clone(), timestamp, signed.clone()), DBRequest::FileWrite(signed.key, signature, timestamp, signed.signature, signed.payload))
        },
        Request::Read(key, subscribe) => (Midstate::Read(id, key, now(), subscribe), DBRequest::FileRead(key)),
        Request::Send(recipient, payload) => {
            let timestamp = now();
            let signature = secret.sign(Id::hash(&(recipient, timestamp, &payload)));
            (Midstate::Sending(id, recipient, signature.clone(), timestamp, payload.clone()), DBRequest::InboxWrite(recipient, signature, timestamp, payload))
        },
        Request::Receive(signed, subscribe) => {
            let identity = resolver.resolve(signed.signer, None).await;
            signed.verify(&identity, &[])?;
            (Midstate::Receive(id, signed.clone(), subscribe), DBRequest::InboxRead(signed.signer, signed.payload))
        }
    })}

    pub fn filter_subscriptions(&mut self, pred: impl Fn(I) -> bool) {
        self.0.iter_mut().for_each(|(_, s)| {s.retain(|i| !pred(*i));});
        self.1.values_mut().for_each(|m| m.retain(|_, v| {v.retain(|i| !pred(*i)); !v.is_empty()}));
    }

    pub async fn response(&mut self, secret: &Secret, midstate: Midstate<I>, response: DBResponse) -> HashMap<I, Response> {match (midstate, response) {
        (Midstate::Creating(id, _, _, _) | Midstate::Read(id, _, _, _), DBResponse::File(Some((signature, timestamp, key_sig, payload)))) =>
            HashMap::from([(id, Response::Read(signature, timestamp, Some((key_sig, payload))))]),
        (Midstate::Creating(id, signature, timestamp, signed), DBResponse::File(None)) => {
            let mut map = self.0.remove(&signed.key).map(|ids| ids.into_iter().map(|i|
                    (i, Response::Read(signature.clone(), timestamp, Some((signed.signature, signed.payload.clone()))))
            ).collect::<HashMap<_, _>>()).unwrap_or_default();
            map.insert(id, Response::Created(signature, timestamp));
            map
        },
        (Midstate::Read(id, key, timestamp, subscribe), DBResponse::File(None)) => {
            if subscribe {self.0.entry(key).or_default().insert(id);}
            let hash = Id::hash(&(key, timestamp, Id::MIN));
            HashMap::from([(id, Response::Read(secret.sign(hash), timestamp, None))])
        },
        (Midstate::Sending(id, recipient, signature, timestamp, payload), DBResponse::InboxWritten) => {
            let mut map = self.1.get_mut(&recipient).map(|m| m.extract_if(|(compare, time), _| match compare {
                Compare::Greater => *time > timestamp,
                Compare::GreaterOrEqual => *time >= timestamp,
                Compare::Equal => *time == timestamp,
                Compare::LesserOrEqual => *time <= timestamp,
                Compare::Lesser => *time < timestamp,
            }).flat_map(|(_, ids)| ids.into_iter().map(|i| 
                (i, Response::Inbox(vec![(signature.clone(), timestamp, payload.clone())]))
            )).collect::<HashMap<_, _>>()).unwrap_or_default();
            map.insert(id, Response::Sent(signature, timestamp));
            map
        }
        (Midstate::Receive(id, signed, subscribe), DBResponse::InboxRead(inbox)) => {
            if subscribe {self.1.entry(signed.signer).or_default().entry(signed.payload).or_default().insert(id);}
            HashMap::from([(id, Response::Inbox(inbox))])
        },
        (m, r) => panic!("Unknown State: {m:?}, {r:?}")
    }}
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
//  }
