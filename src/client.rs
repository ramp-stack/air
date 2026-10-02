use crate::names::{Signature, Name, Id, Resolver};
use crate::storage::{Request, Response};

use std::collections::{HashMap};

use crossfire::{MAsyncTx, AsyncTx, AsyncRx, spsc, mpsc};
use crate::websocket::{Socket, Stream, Sink};

#[derive(Clone, Debug)]
pub struct Client(MAsyncTx<mpsc::List<(Request, AsyncTx<spsc::List<Response>>)>>);
impl Client {
    pub async fn new<R: Resolver + Send + 'static>(mut resolver: R) -> Self {
        let socket = Socket::connect(&mut resolver, Name::orange_me()).await;

        let (mp, sc) = mpsc::build(mpsc::List::new());
        let (sp, rc) = spsc::build(spsc::List::new());
        tokio::spawn(async move { Self::write(socket.0, sc, sp).await});
        tokio::spawn(async move {Self::read(resolver, socket.1, rc).await});
        Client(mp)
    }

    pub async fn send(&self, request: Request) -> AsyncRx<spsc::List<Response>> {
        let (sp, sc) = spsc::build(spsc::List::new());
        self.0.send((request, sp)).await.unwrap();
        sc
    }

    async fn write(mut sink: Sink, rx: AsyncRx<mpsc::List<(Request, AsyncTx<spsc::List<Response>>)>>, tx: AsyncTx<mpsc::List<(Id, AsyncTx<spsc::List<Response>>)>>) {
        while let Ok((request, responder)) = rx.recv().await {
            let hash = Id::hash(&request);
            sink.write(None, postcard::to_allocvec(&request).unwrap()).await;
            tx.send((hash, responder)).await.unwrap();
        }

    }
    async fn read<R: Resolver + 'static>(mut resolver: R, mut stream: Stream, rx: AsyncRx<spsc::List<(Id, AsyncTx<spsc::List<Response>>)>>) {
        let mut index = 0;
        let mut responders: HashMap<u64, (Id, AsyncTx<spsc::List<Response>>)> = HashMap::new();
        loop {tokio::select!{
            (i, bytes) = stream.read() => {
                if let Some((hash, responder)) = responders.get_mut(&i) && let Ok((signature, response)) = postcard::from_bytes::<(Signature, Response)>(&bytes) {
                    let identity = resolver.resolve(Name::orange_me(), None).await;
                    if signature.verify(&identity, &[], Id::hash(&(hash, Id::hash(&response)))).is_ok() {
                        let remove = !matches!(&response, Response::Read(_, None));
                        let _ = responder.send(response).await;
                        if remove { responders.remove(&i); }
                    }
                }
            },
            Ok(responder) = rx.recv() => {
                responders.insert(index, responder);
                index += 1;
            },
            else => break,
        };}
    }
}

//  #[derive(Clone)]
//  pub struct Client(u64, HashMap<u64, Id>);
//  impl Client {
//      pub fn new() -> Self {Client(0, HashMap::new())}

//      pub fn send(&mut self, request: &Request) -> (u64, Vec<u8>) {
//          self.1.insert(self.0, Id::hash(request));
//          self.0 += 1;
//          (self.0-1, postcard::to_allocvec(request).unwrap())
//      }

//      async fn read<R: Resolver + 'static>(mut resolver: R, payload: (u64, Vec<u8>)) -> Option<Response> {
//          if let Some(hash) = self.1.get_mut(&payload.0)
//          && let Ok((signature, response)) = postcard::from_bytes::<(Signature, Response)>(&payload.1) {
//              let identity = resolver.resolve(Name::orange_me(), None).await;
//              if signature.verify(&identity, &[], Id::hash(&(hash, Id::hash(&response)))).is_ok() {
//                  if !matches!(&response, Response::Read(_, None)) {
//                      self.1.remove(&payload.0);
//                  }
//                  return Some(response);
//              }
//          }
//          None
//      }
//  }
