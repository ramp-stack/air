

use crate::names::{Secret, Signature, DefaultResolver};
use crate::names::secp256k1::{Signature as KeySignature};

use crate::storage::{Storage, Request, Response, DBRequest, DBResponse, Compare};

use crate::websocket::{Socket, Stream, Sink};

use crossfire::{MAsyncTx, AsyncRx, spsc, mpsc};
use rusqlite::{Connection, params, OptionalExtension};

use std::collections::HashMap;

type Responder = MAsyncTx<spsc::List<(u64, Response)>>;
type StorageRequest = ((u64, u64), Request, Responder);

#[derive(Clone)]
pub struct Server;
impl Server {
    pub async fn start(secret: Secret) {
        let (tx, rx): (MAsyncTx<_>, _) = mpsc::build(mpsc::List::new());
        let s = secret.clone();
        tokio::spawn(async move {Self::storage(&s, rx).await});

        let mut s_count = 0;
        Socket::listen(&secret, |socket| {
            s_count += 1;
            let (sp, sc) = mpsc::build(mpsc::List::new());

            tokio::spawn(async move { Self::write(socket.0, sc).await});
            let tx = tx.clone();
            tokio::spawn(async move {Self::read(s_count, socket.1, tx, sp).await});
        }).await
    }

    async fn read(s_count: u64, mut stream: Stream, tx: MAsyncTx<mpsc::List<StorageRequest>>, responder: Responder) {
        loop {
            let (r_count, bytes) = stream.read().await;
            if let Ok(request) = postcard::from_bytes(&bytes) {
                tx.send(((s_count, r_count), request, responder.clone())).await.unwrap();
            }
        }
    }

    async fn storage(secret: &Secret, rx: AsyncRx<mpsc::List<StorageRequest>>) {
        let mut resolver = DefaultResolver::start();
        let mut storage = Storage::default();
        let mut responders = HashMap::new();
        let cache = Cache::new();
        while let Ok(((s_count, r_count), request, responder)) = rx.recv().await {
            match storage.request(&mut resolver, secret, (s_count, r_count), request).await {
                Ok((mid, req)) => {
                    responders.insert(s_count, responder);
                    let res = cache.store(req);
                    for ((s_count, r_count), response) in storage.response(secret, mid, res).await {
                        let _ = responders.get(&s_count).unwrap().send((r_count, response)).await;
                    }
                },
                Err(_) => {let _ = responder.send((r_count, Response::InvalidSignature)).await;}
            }
            let dead = responders.extract_if(|_, responder| responder.get_rx_count() == 0).collect::<HashMap<_, _>>();
            storage.filter_subscriptions(|(s_count, _)| dead.contains_key(&s_count));
        }
    }

    async fn write(mut sink: Sink, rx: AsyncRx<spsc::List<(u64, Response)>>) {
        while let Ok((index, response)) = rx.recv().await {
            sink.write(Some(index), postcard::to_allocvec(&response).unwrap()).await;
        }
    }
}

pub struct Cache(Connection);
impl Default for Cache {fn default() -> Self {Self::new()}}
impl Cache {
    pub fn new() -> Self {
        let connection = Connection::open("STORAGE.db").unwrap();

        connection.execute("CREATE TABLE if not exists private(
            key TEXT NOT NULL UNIQUE,
            key_signature BLOB NOT NULL,
            signature BLOB NOT NULL,
            timestamp BLOB NOT NULL,
            payload BLOB NOT NULL
        );", []).unwrap();

        connection.execute("CREATE TABLE if not exists inbox(
            recipient TEXT NOT NULL,
            timestamp INT NOT NULL,
            signature BLOB NOT NULL,
            payload BLOB NOT NULL
        );", []).unwrap();

        Cache(connection)
    }

    fn compare(compare: Compare) -> String {match compare {
        Compare::Greater => ">".to_string(),
        Compare::GreaterOrEqual => ">=".to_string(),
        Compare::Equal => "=".to_string(),
        Compare::LesserOrEqual => "<=".to_string(),
        Compare::Lesser => "<".to_string(),
    }}

    pub fn store(&self, request: DBRequest) -> DBResponse {match request {
        DBRequest::FileWrite(key, signature, timestamp, key_sig, payload) => DBResponse::File(self.0.query_row(
            "INSERT INTO private(key, signature, timestamp, key_signature, payload)
             VALUES (?1, ?2, ?3, ?4, ?5) ON CONFLICT DO UPDATE SET key=?1
             RETURNING signature, key_signature, timestamp, payload;",
            params![
                postcard::to_allocvec(&key).unwrap(),
                postcard::to_allocvec(&signature).unwrap(),
                postcard::to_allocvec(&timestamp).unwrap(),
                postcard::to_allocvec(&key_sig).unwrap(),
                payload
            ],
            |row| Ok((
                postcard::from_bytes::<Signature>(&row.get::<_, Vec<u8>>("signature")?).unwrap(),
                postcard::from_bytes::<u64>(&row.get::<_, Vec<u8>>("timestamp")?).unwrap(),
                postcard::from_bytes::<KeySignature>(&row.get::<_, Vec<u8>>("key_signature")?).unwrap(),
                row.get::<_, Vec<u8>>("payload")?
            ))
        ).optional().unwrap().filter(|r| r.0 != signature)),
        DBRequest::FileRead(key) => DBResponse::File(self.0.query_row(
            "SELECT signature, timestamp, key_signature, payload FROM private WHERE key=?1",
            [postcard::to_allocvec(&key).unwrap()], |row| Ok((
                postcard::from_bytes::<Signature>(&row.get::<_, Vec<u8>>("signature")?).unwrap(),
                postcard::from_bytes::<u64>(&row.get::<_, Vec<u8>>("timestamp")?).unwrap(),
                postcard::from_bytes::<KeySignature>(&row.get::<_, Vec<u8>>("key_signature")?).unwrap(),
                row.get::<_, Vec<u8>>("payload")?
            ))
        ).optional().unwrap()),
        DBRequest::InboxWrite(name, signature, timestamp, payload) => {
            self.0.execute(
                "INSERT INTO inbox(recipient, timestamp, signature, payload) VALUES (?1, ?2, ?3, ?4)",
                params![name.to_string(), timestamp as isize, postcard::to_allocvec(&signature).unwrap(), payload],
            ).unwrap();
            DBResponse::InboxWritten
        },
        DBRequest::InboxRead(name, (compare, timestamp)) => DBResponse::InboxRead(self.0.prepare(&format!(
            "SELECT signature, timestamp, payload FROM inbox WHERE recipient='{name}' AND timestamp{}'{timestamp}'", Self::compare(compare)
        )).unwrap().query_map(
            [], |r| Ok((
                postcard::from_bytes::<Signature>(&r.get::<_, Vec<u8>>(0)?).unwrap(),
                r.get::<_, isize>(1)? as u64,
                r.get::<_, Vec<u8>>(2)?,
            ))
        ).unwrap().collect::<Result<Vec<_>, rusqlite::Error>>().unwrap())
    }}
}

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






//  type S = WebSocketStream<MaybeTlsStream<TcpStream>>;
//  type Open = (Name, AsyncTx<spsc::One<Result<Connection, Error>>>);
//  type Outgoing = (Vec<u8>, Responder);
//  type Responder = AsyncTx<spsc::Array<Response>>;
//  type RReceiver = AsyncRx<spsc::Array<Response>>;
//  type PBFut<T> = Pin<Box<dyn Future<Output = T> + Send>>;

//  pub struct Receiver(AsyncRx<spsc::Array<Response>>);
//  impl Receiver {
//      pub async fn recv(&mut self) -> Response {
//          self.0.recv().await.unwrap()
//      }
//  }

//  #[derive(Debug, Clone)]
//  pub struct Connection(MAsyncTx<mpsc::List<Outgoing>>);
//  impl Connection {
//      pub async fn send(&self, request: Request) -> Receiver {
//          let (tx, rx): (_, AsyncRx<_>) = spsc::build(spsc::Array::new(request.max_responses()));
//          self.0.send((postcard::to_allocvec(&request).unwrap(), tx)).await.unwrap();
//          Receiver(rx)
//      }
//  }

//  #[derive(Debug, Clone)]
//  pub struct Purser(MAsyncTx<mpsc::List<Open>>);
//  impl Purser {
//      pub fn start(resolver: Resolver) -> Self {
//          let (tx, rx) = mpsc::build(mpsc::List::new());
//          spawn(Self::run(resolver, rx));
//          Purser(tx)
//      }

//      pub async fn connect(&self, name: Name) -> Result<Connection, Error> {
//          let (tx, rx): (_, AsyncRx<_>) = spsc::build(spsc::One::new());
//          self.0.send((name, tx)).await.unwrap();
//          rx.recv().await.unwrap()
//      }

//      async fn run(resolver: Resolver, rx: AsyncRx<mpsc::List<Open>>) {
//          let mut open_connections = HashMap::<Name, Connection>::new();
//          while let Ok((name, responder)) = rx.recv().await {
//              //TODO: Do timeout based cleanup after a connection isnt used
//              //open_connections.retain(|_, c| c.0.get_tx_count() > 1);
//              let identity = resolver.resolve(name, None).await;

//              let result = match open_connections.entry(name) {
//                  Entry::Occupied(occupied) => Ok(occupied.get().clone()),
//                  Entry::Vacant(vacant) => {
//                      let (tx, rx) = mpsc::build(mpsc::List::new());
//                      spawn(async move {
//                          let (stream, init) = EncryptionStream::new(&identity, &[]).unwrap();
//                          let url = identity.url().first().unwrap();
//                          let (sink, drain) = stream.split();
//                          //TODO: Be more resiliant to bad connections, try the secondary url
//                          //from the names etc. And automatically handle major errors such as
//                          //downed servers or attacking air servers.
//                          let mut request = url.into_client_request().unwrap();
//                          request.headers_mut().insert("X-Public-Key", hex::encode(postcard::to_allocvec(&init).unwrap()).parse().unwrap());
//                          let (ws_stream, _) = connect_async(request).await.unwrap();
//                          let (write, read) = ws_stream.split();
//                          let (stx, srx) = spsc::build(spsc::List::new());
//                          spawn(Self::write(sink, rx, stx, write));
//                          spawn(Self::read(drain, srx, read));
//                      });
//                      Ok(vacant.insert(Connection(tx)).clone())
//                  }
//              };
//              let _ = responder.send(result).await;
//          }
//      }

//      async fn write(mut sink: Sink, rx: AsyncRx<mpsc::List<Outgoing>>, stx: AsyncTx<mpsc::List<Responder>>, mut write: SplitSink<S, Message>) {
//          while let Ok((request, responder)) = rx.recv().await {
//              
//              let _ = stx.send(responder).await;
//              //TODO: Again be more resilant to bad connections
//              write.send(Message::Binary(postcard::to_allocvec(&sink.encrypt(request)).unwrap().into())).await.unwrap();
//          }
//      }

//      async fn read(mut drain: Drain, srx: AsyncRx<mpsc::List<Responder>>, mut read: SplitStream<S>) {
//          //TODO: Clean up pending requests that are completed or at least ignored
//          let mut pending: HashMap<usize, Responder> = HashMap::new();
//          let mut index = 0;

//          loop {
//              tokio::select! {
//                  Ok(responder) = srx.recv() => {
//                      pending.insert(index, responder);
//                      index += 1;
//                  }
//                  Some(ws_result) = read.next() => {
//                      //TODO: Again be more resilant to bad connections
//                      match ws_result.unwrap() {
//                          Message::Binary(payload) => {
//                              let (index, response): (u64, Response) = postcard::from_bytes(&drain.decrypt(postcard::from_bytes(&payload).unwrap()).unwrap()).unwrap();
//                              let _ = pending.get_mut(&(index as usize)).unwrap().send(response).await;
//                          },
//                          m => panic!("Unexpected Message: {m:?}")
//                      }
//                  }
//                  else => break,
//              }

//              pending.retain(|_, responder| responder.get_tx_count() > 0);
//          }
//      }
//  }

//  #[derive(Clone)]
//  pub struct Chandler {
//      storage: Storage,
//      secret: Secret,
//  }

//  impl Chandler {
//      pub async fn start(secret: Secret) {
//          let storage = Storage::start(&secret);
//          let chandler = Chandler{storage, secret};

//          let listener = TcpListener::bind("0.0.0.0:5702").await.unwrap();
//          while let Ok((stream, _)) = listener.accept().await {
//              spawn(chandler.clone().upgrade(stream));
//          }
//      }

//      async fn upgrade(mut self, stream: TcpStream) {
//          let mut public = None;
//          #[allow(clippy::result_large_err)]
//          match accept_hdr_async(stream, |req: &TungRequest, response: TungResponse| {
//              match req.headers().get("X-Public-Key").and_then(|x| EncryptionStream::receive(&self.secret, postcard::from_bytes(&hex::decode(x.to_str().ok()?).ok()?).ok()?).ok()) {
//                  Some(init) => {
//                      public = Some(init);
//                      Ok(response)
//                  },
//                  None => {
//                      let mut resp = ErrorResponse::new(Some("Invalid/Missing X-Public-Key".to_string()));
//                      *resp.status_mut() = StatusCode::BAD_REQUEST;
//                      Err(resp)
//                  }
//              }
//          }).await {
//              Ok(stream) => self.socket(stream, public.unwrap()).await,
//              Err(e) => println!("Invalid Socket: {e}")
//          }
//      }

//      //Each Socket needs to handle request sequentially, paralization could be used to prepare
//      //decrypted/deserialized responses for the read/write step
//      async fn socket(&mut self, stream: WebSocketStream<TcpStream>, encryption: EncryptionStream) {
//          let (mut write, mut read) = stream.split();
//          let (mut sink, mut drain) = encryption.split();
//          let mut index: usize = 0;
//          let mut futures: FuturesUnordered<PBFut<(usize, Response, RReceiver)>> = FuturesUnordered::new();

//          loop {
//              tokio::select! {
//                  biased;
//                  Some((index, response, receiver)) = futures.next() => {
//                      let _ = write.send(Message::Binary(postcard::to_allocvec(&sink.encrypt(postcard::to_allocvec(&(index, response)).unwrap())).unwrap().into())).await;
//                      if receiver.get_tx_count() > 0 {
//                          futures.push(Box::pin(async move {(index, receiver.recv().await.unwrap(), receiver)}) as _);
//                      }
//                  },
//                  Some(ws_result) = read.next() => {
//                      match ws_result {
//                          Ok(message) => match message {
//                              Message::Binary(payload) => {
//                                  let request = postcard::from_bytes(&drain.decrypt(postcard::from_bytes(&payload).unwrap()).unwrap()).unwrap();
//                                  let srx = self.storage.request(request).await;
//                                  futures.push(Box::pin(async move {(index, srx.recv().await.unwrap(), srx)}) as _);
//                                  index += 1;
//                              },
//                              Message::Close(_) => {
//                                  println!("Client disconnected");
//                                  break;
//                              },
//                              e => {println!("Ignored Request: {e:?}");}
//                          },
//                          Err(e) => {
//                              println!("Client Errored: {:?}", e);
//                              break;
//                          },
//                      }
//                  },
//                  else => {println!("unknown");}
//              }
//          }
//      }
//  }

//  #[cfg(test)]
//  mod test {
//    //use super::*;
//    //use crate::storage::{Request, Response, Compare, Metadata};
//    //use crate::names::{Name, secp256k1::{SecretKey, Signed as KeySigned}, Resolver, Id, Signed, Secret};

//    //fn metadata(response: Response) -> Option<(Id, usize)> {
//    //    match response {
//    //        Response::Receipt(m) => Some((m.as_ref().hash, m.as_ref().len)),
//    //        _ => None,
//    //    }
//    //}

//    //fn private(response: Response) -> Option<Vec<u8>> {
//    //    match response {
//    //        Response::Private(_, p) => Some(p.into_inner()),
//    //        _ => None,
//    //    }
//    //}

//    //fn inbox(response: Response) -> Option<Vec<Vec<u8>>> {
//    //    match response {
//    //        Response::Inbox(i) => Some(i.into_iter().map(|(_, p)| p).collect()),
//    //        _ => None,
//    //    }
//    //}

//    //#[tokio::test]
//    //async fn test_private() {
//    //    let purser = Purser::start(Resolver);
//    //    let connection = purser.connect(Name::orange_me()).await.unwrap();
//    //    let key = SecretKey::new();
//    //    let item = KeySigned::new(&key, b"hello".to_vec());
//    //    let other = KeySigned::new(&key, b"other".to_vec());
//    //    let hash = Metadata::new(item.as_ref()).hash;
//    //    assert_eq!(metadata(connection.send(Request::Read(key.public_key(), false)).await), Some((Id::MIN, 0)));
//    //    assert_eq!(metadata(connection.send(Request::Create(item.clone(), false)).await), Some((hash, 5)));
//    //    assert_eq!(metadata(connection.send(Request::Create(other.clone(), false)).await), Some((hash, 5)));
//    //    assert_eq!(private(connection.send(Request::Create(other, true)).await), Some(item.clone().into_inner()));
//    //    assert_eq!(private(connection.send(Request::Read(key.public_key(), true)).await), Some(item.clone().into_inner()));
//    //    assert_eq!(metadata(connection.send(Request::Read(key.public_key(), false)).await), Some((hash, 5)));
//    //    assert_eq!(metadata(connection.send(Request::Create(KeySigned::new(&key, b"goodbye".to_vec()), false)).await), Some((hash, 5)));
//    //}

//    //#[tokio::test]
//    //async fn test_inbox() {
//    //    let purser = Purser::start(Resolver);
//    //    let connection = purser.connect(Name::orange_me()).await.unwrap();
//    //    let secret = Secret::new();
//    //    let name = secret.name();
//    //    let item = b"hello bob".to_vec();
//    //    let hash = Id::hash(&item);
//    //    let time = (Compare::GreaterOrEqual, 0);
//    //    assert_eq!(inbox(connection.send(Request::Receive(Signed::new(&secret, time).unwrap())).await), Some(vec![]));
//    //    assert_eq!(metadata(connection.send(Request::Send(name, item.clone())).await), Some((hash, 9)));
//    //    assert_eq!(inbox(connection.send(Request::Receive(Signed::new(&secret, time).unwrap())).await), Some(vec![item.clone()]));
//    //    assert_eq!(metadata(connection.send(Request::Send(name, item.clone())).await), Some((hash, 9)));
//    //    assert_eq!(inbox(connection.send(Request::Receive(Signed::new(&secret, time).unwrap())).await), Some(vec![item.clone(), item]));
//    //}
//  }
