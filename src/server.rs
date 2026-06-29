use crate::names::{Secret, EncryptionStream};
use crate::storage::{Storage, Request, Response};

use futures_util::{StreamExt, SinkExt};

use crossfire::{MAsyncTx, AsyncTx, AsyncRx, spsc, mpsc};

use tokio::net::{TcpListener, TcpStream};
use tokio::spawn;

use tokio_tungstenite::{accept_hdr_async, tungstenite, WebSocketStream};
use tungstenite::handshake::server::{Request as TungRequest, Response as TungResponse, ErrorResponse};
use tungstenite::protocol::Message;
use tungstenite::http::StatusCode;

use futures_util::stream::{SplitStream, FuturesUnordered};
use std::pin::Pin;

use tokio_tungstenite::{connect_async, MaybeTlsStream};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;

use futures_util::stream::{SplitSink};

use std::collections::HashMap;
use std::collections::hash_map::Entry;

use crate::names::{Error, Resolver, Name, Sink, Drain};

type S = WebSocketStream<MaybeTlsStream<TcpStream>>;
type Open = (Name, AsyncTx<spsc::One<Result<Connection, Error>>>);
type Outgoing = (Vec<u8>, Responder);
type Responder = AsyncTx<spsc::Array<Response>>;
type RReceiver = AsyncRx<spsc::Array<Response>>;
type PBFut<T> = Pin<Box<dyn Future<Output = T> + Send>>;

pub struct Receiver(AsyncRx<spsc::Array<Response>>);
impl Receiver {
    pub async fn recv(&mut self) -> Response {
        self.0.recv().await.unwrap()
    }
}

#[derive(Debug, Clone)]
pub struct Connection(MAsyncTx<mpsc::List<Outgoing>>);
impl Connection {
    pub async fn send(&self, request: Request) -> Receiver {
        let (tx, rx): (_, AsyncRx<_>) = spsc::build(spsc::Array::new(request.max_responses()));
        self.0.send((postcard::to_allocvec(&request).unwrap(), tx)).await.unwrap();
        Receiver(rx)
    }
}

#[derive(Debug, Clone)]
pub struct Purser(MAsyncTx<mpsc::List<Open>>);
impl Purser {
    pub fn start(resolver: Resolver) -> Self {
        let (tx, rx) = mpsc::build(mpsc::List::new());
        spawn(Self::run(resolver, rx));
        Purser(tx)
    }

    pub async fn connect(&self, name: Name) -> Result<Connection, Error> {
        let (tx, rx): (_, AsyncRx<_>) = spsc::build(spsc::One::new());
        self.0.send((name, tx)).await.unwrap();
        rx.recv().await.unwrap()
    }

    async fn run(resolver: Resolver, rx: AsyncRx<mpsc::List<Open>>) {
        let mut open_connections = HashMap::<Name, Connection>::new();
        while let Ok((name, responder)) = rx.recv().await {
            //TODO: Do timeout based cleanup after a connection isnt used
            //open_connections.retain(|_, c| c.0.get_tx_count() > 1);
            let identity = resolver.resolve(name, None).await;

            let result = match open_connections.entry(name) {
                Entry::Occupied(occupied) => Ok(occupied.get().clone()),
                Entry::Vacant(vacant) => {
                    let (tx, rx) = mpsc::build(mpsc::List::new());
                    spawn(async move {
                        let (stream, init) = EncryptionStream::new(&identity, &[]).unwrap();
                        let url = identity.url().first().unwrap();
                        let (sink, drain) = stream.split();
                        //TODO: Be more resiliant to bad connections, try the secondary url
                        //from the names etc. And automatically handle major errors such as
                        //downed servers or attacking air servers.
                        let mut request = url.into_client_request().unwrap();
                        request.headers_mut().insert("X-Public-Key", hex::encode(postcard::to_allocvec(&init).unwrap()).parse().unwrap());
                        let (ws_stream, _) = connect_async(request).await.unwrap();
                        let (write, read) = ws_stream.split();
                        let (stx, srx) = spsc::build(spsc::List::new());
                        spawn(Self::write(sink, rx, stx, write));
                        spawn(Self::read(drain, srx, read));
                    });
                    Ok(vacant.insert(Connection(tx)).clone())
                }
            };
            let _ = responder.send(result).await;
        }
    }

    async fn write(mut sink: Sink, rx: AsyncRx<mpsc::List<Outgoing>>, stx: AsyncTx<mpsc::List<Responder>>, mut write: SplitSink<S, Message>) {
        while let Ok((request, responder)) = rx.recv().await {
            
            let _ = stx.send(responder).await;
            //TODO: Again be more resilant to bad connections
            write.send(Message::Binary(postcard::to_allocvec(&sink.encrypt(request)).unwrap().into())).await.unwrap();
        }
    }

    async fn read(mut drain: Drain, srx: AsyncRx<mpsc::List<Responder>>, mut read: SplitStream<S>) {
        //TODO: Clean up pending requests that are completed or at least ignored
        let mut pending: HashMap<usize, Responder> = HashMap::new();
        let mut index = 0;

        loop {
            tokio::select! {
                Ok(responder) = srx.recv() => {
                    pending.insert(index, responder);
                    index += 1;
                }
                Some(ws_result) = read.next() => {
                    //TODO: Again be more resilant to bad connections
                    match ws_result.unwrap() {
                        Message::Binary(payload) => {
                            let (index, response): (u64, Response) = postcard::from_bytes(&drain.decrypt(postcard::from_bytes(&payload).unwrap()).unwrap()).unwrap();
                            let _ = pending.get_mut(&(index as usize)).unwrap().send(response).await;
                        },
                        m => panic!("Unexpected Message: {m:?}")
                    }
                }
                else => break,
            }

            pending.retain(|_, responder| responder.get_tx_count() > 0);
        }
    }
}

#[derive(Clone)]
pub struct Chandler {
    storage: Storage,
    secret: Secret,
}

impl Chandler {
    pub async fn start(secret: Secret) {
        let storage = Storage::start(&secret);
        let chandler = Chandler{storage, secret};

        let listener = TcpListener::bind("0.0.0.0:5702").await.unwrap();
        while let Ok((stream, _)) = listener.accept().await {
            spawn(chandler.clone().upgrade(stream));
        }
    }

    async fn upgrade(mut self, stream: TcpStream) {
        let mut public = None;
        #[allow(clippy::result_large_err)]
        match accept_hdr_async(stream, |req: &TungRequest, response: TungResponse| {
            match req.headers().get("X-Public-Key").and_then(|x| EncryptionStream::receive(&self.secret, postcard::from_bytes(&hex::decode(x.to_str().ok()?).ok()?).ok()?).ok()) {
                Some(init) => {
                    public = Some(init);
                    Ok(response)
                },
                None => {
                    let mut resp = ErrorResponse::new(Some("Invalid/Missing X-Public-Key".to_string()));
                    *resp.status_mut() = StatusCode::BAD_REQUEST;
                    Err(resp)
                }
            }
        }).await {
            Ok(stream) => self.socket(stream, public.unwrap()).await,
            Err(e) => println!("Invalid Socket: {e}")
        }
    }

    //Each Socket needs to handle request sequentially, paralization could be used to prepare
    //decrypted/deserialized responses for the read/write step
    async fn socket(&mut self, stream: WebSocketStream<TcpStream>, encryption: EncryptionStream) {
        let (mut write, mut read) = stream.split();
        let (mut sink, mut drain) = encryption.split();
        let mut index: usize = 0;
        let mut futures: FuturesUnordered<PBFut<(usize, Response, RReceiver)>> = FuturesUnordered::new();

        loop {
            tokio::select! {
                biased;
                Some((index, response, receiver)) = futures.next() => {
                    let _ = write.send(Message::Binary(postcard::to_allocvec(&sink.encrypt(postcard::to_allocvec(&(index, response)).unwrap())).unwrap().into())).await;
                    if receiver.get_tx_count() > 0 {
                        futures.push(Box::pin(async move {(index, receiver.recv().await.unwrap(), receiver)}) as _);
                    }
                },
                Some(ws_result) = read.next() => {
                    match ws_result {
                        Ok(message) => match message {
                            Message::Binary(payload) => {
                                let request = postcard::from_bytes(&drain.decrypt(postcard::from_bytes(&payload).unwrap()).unwrap()).unwrap();
                                let srx = self.storage.request(request).await;
                                futures.push(Box::pin(async move {(index, srx.recv().await.unwrap(), srx)}) as _);
                                index += 1;
                            },
                            Message::Close(_) => {
                                println!("Client disconnected");
                                break;
                            },
                            e => {println!("Ignored Request: {e:?}");}
                        },
                        Err(e) => {
                            println!("Client Errored: {:?}", e);
                            break;
                        },
                    }
                },
                else => {println!("unknown");}
            }
        }
    }
}

#[cfg(test)]
mod test {
  //use super::*;
  //use crate::storage::{Request, Response, Compare, Metadata};
  //use crate::names::{Name, secp256k1::{SecretKey, Signed as KeySigned}, Resolver, Id, Signed, Secret};

  //fn metadata(response: Response) -> Option<(Id, usize)> {
  //    match response {
  //        Response::Receipt(m) => Some((m.as_ref().hash, m.as_ref().len)),
  //        _ => None,
  //    }
  //}

  //fn private(response: Response) -> Option<Vec<u8>> {
  //    match response {
  //        Response::Private(_, p) => Some(p.into_inner()),
  //        _ => None,
  //    }
  //}

  //fn inbox(response: Response) -> Option<Vec<Vec<u8>>> {
  //    match response {
  //        Response::Inbox(i) => Some(i.into_iter().map(|(_, p)| p).collect()),
  //        _ => None,
  //    }
  //}

  //#[tokio::test]
  //async fn test_private() {
  //    let purser = Purser::start(Resolver);
  //    let connection = purser.connect(Name::orange_me()).await.unwrap();
  //    let key = SecretKey::new();
  //    let item = KeySigned::new(&key, b"hello".to_vec());
  //    let other = KeySigned::new(&key, b"other".to_vec());
  //    let hash = Metadata::new(item.as_ref()).hash;
  //    assert_eq!(metadata(connection.send(Request::Read(key.public_key(), false)).await), Some((Id::MIN, 0)));
  //    assert_eq!(metadata(connection.send(Request::Create(item.clone(), false)).await), Some((hash, 5)));
  //    assert_eq!(metadata(connection.send(Request::Create(other.clone(), false)).await), Some((hash, 5)));
  //    assert_eq!(private(connection.send(Request::Create(other, true)).await), Some(item.clone().into_inner()));
  //    assert_eq!(private(connection.send(Request::Read(key.public_key(), true)).await), Some(item.clone().into_inner()));
  //    assert_eq!(metadata(connection.send(Request::Read(key.public_key(), false)).await), Some((hash, 5)));
  //    assert_eq!(metadata(connection.send(Request::Create(KeySigned::new(&key, b"goodbye".to_vec()), false)).await), Some((hash, 5)));
  //}

  //#[tokio::test]
  //async fn test_inbox() {
  //    let purser = Purser::start(Resolver);
  //    let connection = purser.connect(Name::orange_me()).await.unwrap();
  //    let secret = Secret::new();
  //    let name = secret.name();
  //    let item = b"hello bob".to_vec();
  //    let hash = Id::hash(&item);
  //    let time = (Compare::GreaterOrEqual, 0);
  //    assert_eq!(inbox(connection.send(Request::Receive(Signed::new(&secret, time).unwrap())).await), Some(vec![]));
  //    assert_eq!(metadata(connection.send(Request::Send(name, item.clone())).await), Some((hash, 9)));
  //    assert_eq!(inbox(connection.send(Request::Receive(Signed::new(&secret, time).unwrap())).await), Some(vec![item.clone()]));
  //    assert_eq!(metadata(connection.send(Request::Send(name, item.clone())).await), Some((hash, 9)));
  //    assert_eq!(inbox(connection.send(Request::Receive(Signed::new(&secret, time).unwrap())).await), Some(vec![item.clone(), item]));
  //}
}
