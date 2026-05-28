use super::storage::{Request, Response};

use tokio_tungstenite::{connect_async, WebSocketStream, MaybeTlsStream, tungstenite};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tungstenite::protocol::Message;

use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{SinkExt, StreamExt};

use tokio::net::TcpStream;
use tokio::task::spawn;

use std::collections::HashMap;
use std::collections::hash_map::Entry;

use crate::names::{Error, Resolver, Name, Sink, Drain, EncryptionStream};
use crossfire::{MAsyncTx, AsyncTx, AsyncRx, mpsc, spsc};

type S = WebSocketStream<MaybeTlsStream<TcpStream>>;
type Open = (Name, AsyncTx<spsc::One<Result<Connection, Error>>>);
type Outgoing = (Vec<u8>, Responder);
type Responder = AsyncTx<spsc::One<Response>>;

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

    async fn run(mut resolver: Resolver, rx: AsyncRx<mpsc::List<Open>>) {
        let mut open_connections = HashMap::<Name, Connection>::new();
        while let Ok((name, responder)) = rx.recv().await {
            //TODO: Do timeout based cleanup after a connection isnt used
            //open_connections.retain(|_, c| c.0.get_tx_count() > 1);
            let identity = resolver.resolve(&name).await.unwrap();
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
                        spawn(Connection::write(sink, rx, stx, write));
                        spawn(Connection::read(drain, srx, read));
                    });
                    Ok(vacant.insert(Connection(tx)).clone())
                }
            };
            let _ = responder.send(result).await;
        }
    }
}

#[derive(Debug, Clone)]
pub struct Connection(MAsyncTx<mpsc::List<Outgoing>>);
impl Connection {
    pub async fn send(&self, request: Request) -> Response {
        let (tx, rx): (_, AsyncRx<_>) = spsc::build(spsc::One::new());
        self.0.send((postcard::to_allocvec(&request).unwrap(), tx)).await.unwrap();
        rx.recv().await.unwrap()
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
                    println!("responder: {index}");
                    index += 1;
                }
                Some(ws_result) = read.next() => {
                    //TODO: Again be more resilant to bad connections
                    match ws_result.unwrap() {
                        Message::Binary(payload) if payload.len() > 20 => {
                            let (index, response): (u64, Response) = postcard::from_bytes(&drain.decrypt(postcard::from_bytes(&payload).unwrap()).unwrap()).unwrap();
                            pending.remove(&(index as usize)).unwrap().send(response).await.unwrap();
                        },
                        m => panic!("Unexpected Message: {m:?}")
                    }
                }
                else => break,
            }
        }
    }
}
