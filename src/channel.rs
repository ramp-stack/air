use serde::{Serialize, Deserialize};

use crate::names::{secp256k1::{Signed as KeySigned, SecretKey, Encrypted as KeyEncrypted}, Encrypted, Secret, Signed, Name, Id, now};
use crate::storage::{Compare, Request, Response};
use crate::Handle;

use crossfire::{MAsyncTx, AsyncTx, AsyncRx, MTx, mpsc, spsc};

pub const CHANNEL: &str = "CHANNEL";

pub type Data = Option<(Name, Vec<u8>)>;

#[derive(Debug)]
pub struct Stream(Channel, AsyncRx<spsc::List<(Channel, Data)>>);
impl Stream {
    pub fn channel(&self) -> &Channel {&self.0}
    pub async fn read(&mut self) -> (u64, Option<(Name, Vec<u8>)>) {
        let (channel, data) = self.1.recv().await.unwrap();
        self.0 = channel;
        (self.0.timestamp, data)
    }
}

#[derive(Clone, Debug)]
pub struct Sink(MAsyncTx<spsc::List<Vec<u8>>>);
impl Sink {
    pub async fn write(&self, data: Vec<u8>) {self.0.send(data).await.unwrap()}
    pub fn write_sync(&self, data: Vec<u8>) {MTx::from(self.0.clone()).send(data).unwrap()}
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Clone, Copy, Debug, Default)]
pub struct Channel {
    //pub servers: Vec<Name>,
    pub key: SecretKey,
    pub index: u64,
    pub timestamp: u64,
}

impl Channel {
    pub fn new(key: SecretKey) -> Self {Channel{key, index: 0, timestamp: 0}}

    ///It is assumed that the channels path is equal to the path of the secret
    ///Its up to you to ensure the secret is at the correct path for this channel
    pub fn start(mut self, handle: Handle, secret: Secret) -> (Stream, Sink) {
        let secret = secret.derive(&[Id::hash(CHANNEL)]);
        let (write, rx): (MAsyncTx<_>, AsyncRx<_>) = mpsc::build(mpsc::List::new());
        let (tx, read): (AsyncTx<_>, AsyncRx<_>) = spsc::build(spsc::List::new());

        let channel = self;
        handle.handle.spawn(async move {
            let server = Name::orange_me();
            let key = self.key.derive(&[Id::hash(&server)]);
            let connection = handle.purser.connect(server).await.unwrap();

            let mut request: Option<(Vec<u8>, Vec<u8>)> = None;
            loop {
                let key = key.derive(&[Id::hash(&self.index)]);
                let public = key.public_key();
                match &mut request {
                    Some(_) => {},
                    none => {*none = rx.try_recv().ok().map(|d: Vec<u8>|{
                        (d.clone(), postcard::to_allocvec(&Signed::new(&secret, d)).unwrap())
                    });}
                }

                if let Some((signature, time, key_sig, payload)) = match request.as_ref() {
                    Some((_, data)) => {
                        let encrypted = postcard::to_allocvec(&public.encrypt(data.clone())).unwrap();
                        let hash = Id::hash(&encrypted);
                        let response = connection.send(Request::Create(KeySigned::new(&key, encrypted))).await;
                        match response{
                            Response::Create(signature, time) => {
                                let identity = handle.resolver.resolve(server, Some(time)).await;
                                if signature.verify(&identity, &[], Id::hash(&(public, time, hash))).is_ok() 
                                && self.timestamp < time {
                                    self.timestamp = time;
                                    self.index += 1;
                                    tx.send((self, request.take().map(|(d, _)| (secret.name(), d)))).await.unwrap()
                                } else {panic!("Bad Air Server");}
                                None
                            },
                            Response::Read(signature, time, Some((key_sig, payload))) => Some((signature, time, key_sig, payload)),
                            _ => {todo!()}
                        }
                    },
                    None => {
                        let subscription = connection.clone();
                        tokio::select! {
                            Response::Read(signature, time, Some((key_sig, payload))) = subscription.send(Request::Read(public, true)) => {
                                Some((signature, time, key_sig, payload))
                            },
                            Ok(d) = rx.recv() => {
                                request = Some((d.clone(), postcard::to_allocvec(&Signed::new(&secret, d)).unwrap()));
                                None
                            }
                            else => {todo!()}
                        }
                    }
                } {
                    self.index += 1;
                    let hash = Id::hash(&payload);
                    let identity = handle.resolver.resolve(server, Some(time)).await;
                    if signature.verify(&identity, &[], Id::hash(&(public, time, hash))).is_ok()
                    && key_sig.verify(&public, hash).is_ok() {
                        let result = if time > self.timestamp {
                            self.timestamp = time;
                            if let Some(signed) = postcard::from_bytes::<KeyEncrypted>(&payload).ok().and_then(|e| key.decrypt(e).ok().and_then(|d| postcard::from_bytes::<Signed<Vec<u8>>>(&d).ok())) {
                                let identity = handle.resolver.resolve(signed.signer, Some(time)).await;
                                if signed.verify(&identity, secret.path()).is_ok() {
                                    Some((signed.signer, signed.payload))
                                } else {println!("bad signature"); None}
                            } else {println!("bad encryption/serialization"); None}
                        } else {println!("bad time"); None};
                        tx.send((self, result)).await.unwrap();
                    } else {panic!("Bad Air Server");}
                }
            }
        });
        (Stream(channel, read), Sink(write))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn channel() {
        let secret = Secret::new();
        let key = secret.harden();
        let name = secret.name();

        let (handle, remote) = crate::runtime::Handle::new();
        let handle = Handle::new(handle, secret.clone());

        let (mut stream, sink) = Channel::new(key).start(handle.clone(), secret);

        handle.handle.block_on(async {
            let content = b"hello".to_vec();
            sink.write(content.clone()).await;
            let (timestamp, data) = stream.read().await;
            assert_eq!(stream.channel(), &Channel{key, index: 1, timestamp});
            assert_eq!(data, Some((name, content.clone())));

            let content2 = b"goodbye".to_vec();
            sink.write(content2.clone()).await;
            let (timestamp2, data2) = stream.read().await;
            assert_eq!(stream.channel(), &Channel{key, index: 2, timestamp: timestamp2});
            assert_eq!(data2, Some((name, content2.clone())));
        });
    }
}

#[derive(Debug)]
pub struct InboxHandler(Inbox, AsyncRx<spsc::List<(u64, Option<Vec<u8>>)>>);
impl InboxHandler {
    pub fn inbox(&self) -> &Inbox {&self.0}

    pub async fn read(&mut self) -> (u64, Option<Vec<u8>>) {
        let (time, data) = self.1.recv().await.unwrap();
        self.0.0 = time;
        (time, data)
    }

    pub fn send(handle: Handle, name: Name, location: Vec<u8>) {
        handle.handle.spawn(async move {
            let identity = handle.resolver.resolve(name, None).await;
            let home = *identity.servers().first().unwrap();
            let conn = handle.purser.connect(home).await.unwrap();
            //Verify receipet
            println!("sending to {:?}", name);
            conn.send(Request::Send(name, postcard::to_allocvec(&identity.encrypt(&[], location)).unwrap())).await;
        });
    }
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, Default)]
pub struct Inbox(u64);
impl Inbox {
    pub fn start(mut self, handle: Handle) -> InboxHandler {
        let (tx, rx): (AsyncTx<_>, _) = spsc::build(spsc::List::new());

        handle.handle.spawn(async move { loop {
            let identity = handle.resolver.resolve(handle.name, None).await;
            let home = *identity.servers().first().unwrap();
            let conn = handle.purser.connect(home).await.unwrap();
            match conn.send(Request::Receive(Signed::new(&handle.secret, (Compare::Greater, self.0)))).await {
                Response::Inbox(received) => {
                    let home_identity = handle.resolver.resolve(home, None).await;
                    for (signature, timestamp, data) in received {
                        if signature.verify(&home_identity, &[], Id::hash(&(handle.name, timestamp, &data))).is_ok() && timestamp > self.0 {
                            self.0 = timestamp;
                            let data = postcard::from_bytes::<Encrypted>(&data).ok().and_then(|d| handle.secret.decrypt(d).ok());
                            tx.send((timestamp, data)).await.unwrap();
                        } else {panic!("Bad Air Server");}
                    }
                },
                response => {panic!("Bad Air Server: {response:?}");}
            }
        }});
        InboxHandler(self, rx)
    }
}
