use crate::names::Secret;

use futures_util::{StreamExt, SinkExt};

use tokio::net::{TcpListener, TcpStream};

use tokio_tungstenite::{accept_hdr_async, tungstenite, WebSocketStream};
use tungstenite::handshake::server::{Request as TungRequest, Response as TungResponse, ErrorResponse};
use tungstenite::protocol::Message;
use tungstenite::http::StatusCode;

use futures_util::stream::SplitStream;

use tokio_tungstenite::client_async;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;

use futures_util::stream::{SplitSink};

use crate::names::{Resolver, Name, self};

type S = WebSocketStream<TcpStream>;

pub struct Stream(SplitStream<S>, names::Drain, Option<u64>);
impl Stream {
    pub async fn read(&mut self) -> (u64, Vec<u8>) {
        loop {
            if let Message::Binary(bytes) = self.0.next().await.unwrap().unwrap() && (self.2.is_none() || (self.2.is_some() && bytes.len() > 8)) {
                break match &mut self.2 {
                    Some(index) => {
                        *index += 1;
                        (*index-1, self.1.decrypt(bytes.to_vec()).unwrap())
                    },
                    None => {
                        let mut result = self.1.decrypt(bytes.to_vec()).unwrap();
                        (u64::from_le_bytes(result.split_off(result.len()-8).try_into().unwrap()), result)
                    }
                };
            }
        }
    }
}

pub struct Sink(names::Sink, SplitSink<S, Message>);
impl Sink {
    pub async fn write(&mut self, response: Option<u64>, mut bytes: Vec<u8>) {
        if let Some(r) = response {bytes.extend(r.to_le_bytes());}
        self.1.send(Message::Binary(self.0.encrypt(bytes).into())).await.unwrap();
    }
}

pub struct Socket(pub Sink, pub Stream);
impl Socket {
    pub async fn connect<R: Resolver>(resolver: &mut R, name: Name) -> Self {
        let identity = resolver.resolve(name, None).await;
        let (en_stream, srequest) = names::Stream::send(&identity, &[]);

        let url = identity.url().first().unwrap();
        //TODO: Be more resiliant to bad connections, try the secondary url
        //from the names etc. And automatically handle major errors such as
        //downed servers or attacking air servers.
        let mut request = format!("ws://{}", url).into_client_request().unwrap();
        request.headers_mut().insert("X-Public-Key", hex::encode(postcard::to_allocvec(&srequest).unwrap()).parse().unwrap());
        let tcp = TcpStream::connect(url).await.unwrap();
        let (ws_stream, _) = client_async(request, tcp).await.unwrap();

        //let (ws_stream, _) = connect_async(request).await.unwrap();
        let (write, read) = ws_stream.split();
        let (sink, drain) = en_stream.split();
        Socket(Sink(sink, write), Stream(read, drain, None))
    }

    pub async fn listen(secret: &Secret, mut handle: impl FnMut(Socket)) {
        let listener = TcpListener::bind("0.0.0.0:5702").await.unwrap();
        while let Ok((stream, _)) = listener.accept().await {
            let mut en_stream = None;
            #[allow(clippy::result_large_err)]
            match accept_hdr_async(stream, |req: &TungRequest, response: TungResponse| {
                match req.headers().get("X-Public-Key").and_then(|x| {
                    Some(names::Stream::receive(secret, postcard::from_bytes(&hex::decode(x.to_str().ok()?).ok()?).ok()?))
                }) {
                    Some(s) => {
                        en_stream = Some(s);
                        Ok(response)
                    },
                    None => {
                        let mut resp = ErrorResponse::new(Some("Invalid/Missing X-Public-Key".to_string()));
                        *resp.status_mut() = StatusCode::BAD_REQUEST;
                        Err(resp)
                    }
                }
            }).await {
                Ok(ws_stream) => {
                    let (write, read) = ws_stream.split();
                    let (sink, drain) = en_stream.unwrap().split();
                    (handle)(Socket(Sink(sink, write), Stream(read, drain, Some(0))))
                },
                Err(e) => println!("Invalid Socket: {e}")
            }
        }
    }
}
