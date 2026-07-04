use serde::{Serialize, Deserialize};

use crate::names::{secp256k1::{Signed as KeySigned, SecretKey, Encrypted as KeyEncrypted}, Encrypted, Secret, Signed, Name, Id};
use crate::storage::{Compare, Request, Response};
use crate::Air;

use crossfire::{MAsyncTx, AsyncTx, AsyncRx, mpsc, spsc};

pub const CHANNEL: &str = "CHANNEL";

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Event {
    Head,
    Garbage,
    Data(Name, Vec<u8>, Option<Id>), 
}

#[derive(Debug)]
pub struct Stream(Channel, AsyncRx<spsc::List<(Channel, Event)>>);
impl Stream {
    pub fn channel(&self) -> &Channel {&self.0}
    pub async fn read(&mut self) -> (u64, Event) {
        let (channel, event) = self.1.recv().await.unwrap();
        self.0 = channel;
        (self.0.timestamp, event)
    }
}

#[derive(Clone, Debug)]
pub struct Sink(MAsyncTx<spsc::List<(Id, Vec<u8>)>>);
impl Sink {
    pub async fn write(&self, data: Vec<u8>) -> Id {
        let id = Id::random();
        self.0.send((id, data)).await.unwrap();
        id
    }
    pub fn write_sync(&self, data: Vec<u8>) -> Id {
        let id = Id::random();
        self.0.clone().try_send((id, data)).unwrap();
        id
    }
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
    pub fn start(mut self, air: Air, secret: Secret) -> (Stream, Sink) {
        let secret = secret.derive(&[Id::hash(CHANNEL)]);
        let (write, rx): (MAsyncTx<_>, AsyncRx<_>) = mpsc::build(mpsc::List::new());
        let (tx, read): (AsyncTx<_>, AsyncRx<_>) = spsc::build(spsc::List::new());

        let channel = self;
        air.handle.spawn(async move {
            let mut head = false;
            let server = Name::orange_me();
            let key = self.key.derive(&[Id::hash(&server)]);
            let connection = air.purser.connect(server).await.unwrap();

            let mut request: Option<(Vec<u8>, Vec<u8>, Id)> = None;
            loop {
                let key = key.derive(&[Id::hash(&self.index)]);
                let public = key.public_key();
                match &mut request {
                    Some(_) => {},
                    none => {*none = rx.try_recv().ok().map(|tuple: (Id, Vec<u8>)|{
                        (tuple.1.clone(), postcard::to_allocvec(&Signed::new(&secret, tuple.1)).unwrap(), tuple.0)
                    });}
                }

                if let Some((signature, time, key_sig, payload)) = match request.as_ref() {
                    Some((_, data, _)) => {
                        let encrypted = postcard::to_allocvec(&public.encrypt(data.clone())).unwrap();
                        let hash = Id::hash(&encrypted);
                        let response = connection.send(Request::Create(KeySigned::new(&key, encrypted))).await.recv().await;
                        match response{
                            Response::Create(signature, time) => {
                                let identity = air.resolver.resolve(server, Some(time)).await;
                                if signature.verify(&identity, &[], Id::hash(&(public, time, hash))).is_ok() 
                                && self.timestamp < time {
                                    self.timestamp = time;
                                    self.index += 1;
                                    tx.send((self, request.take().map(|(d, _, rid)| Event::Data(secret.name(), d, Some(rid))).expect("Bad Air Server"))).await.unwrap()
                                } else {panic!("Bad Air Server");}
                                None
                            },
                            Response::Read(signature, time, Some((key_sig, payload))) => Some((signature, time, key_sig, payload)),
                            _ => {panic!("Bad Air Server")}
                        }
                    },
                    None => {
                        let mut subscription = connection.clone().send(Request::Read(public, true)).await;
                        loop {tokio::select! {
                            Response::Read(signature, time, data) = subscription.recv() => {
                                if let Some((key_sig, payload)) = data {
                                    break Some((signature, time, key_sig, payload));
                                } else if !head {
                                    let identity = air.resolver.resolve(server, Some(time)).await;
                                    if signature.verify(&identity, &[], Id::hash(&(public, time, Id::MIN))).is_err() {
                                        panic!("Bad Air Server");
                                    }
                                    head = true;
                                    tx.send((self, Event::Head)).await.unwrap();
                                }
                            },
                            Ok((rid, d)) = rx.recv() => {
                                request = Some((d.clone(), postcard::to_allocvec(&Signed::new(&secret, d)).unwrap(), rid));
                                break None;
                            }
                            else => {panic!("Bad Air Server")}
                        }}
                    }
                } {
                    self.index += 1;
                    let hash = Id::hash(&payload);
                    let identity = air.resolver.resolve(server, Some(time)).await;
                    if signature.verify(&identity, &[], Id::hash(&(public, time, hash))).is_ok()
                    && key_sig.verify(&public, hash).is_ok() {
                        let result = if time > self.timestamp {
                            self.timestamp = time;
                            if let Some(signed) = postcard::from_bytes::<KeyEncrypted>(&payload).ok().and_then(|e| key.decrypt(e).ok().and_then(|d| postcard::from_bytes::<Signed<Vec<u8>>>(&d).ok())) {
                                let identity = air.resolver.resolve(signed.signer, Some(time)).await;
                                if signed.verify(&identity, secret.path()).is_ok() {
                                    Some((signed.signer, signed.payload))
                                } else {println!("bad signature"); None}
                            } else {println!("bad encryption/serialization"); None}
                        } else {println!("bad time"); None};
                        tx.send((self, result.map(|(a, b)| Event::Data(a, b, None)).unwrap_or(Event::Garbage))).await.unwrap();
                    } else {panic!("Bad Air Server");}
                }
            }
        });
        (Stream(channel, read), Sink(write))
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

    pub fn send(air: Air, name: Name, location: Vec<u8>) {
        air.handle.spawn(async move {
            let identity = air.resolver.resolve(name, None).await;
            let home = *identity.servers().first().unwrap();
            let conn = air.purser.connect(home).await.unwrap();
            conn.send(Request::Send(name, postcard::to_allocvec(&identity.encrypt(&[], location)).unwrap())).await;
        });
    }
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, Default)]
pub struct Inbox(u64);
impl Inbox {
    pub fn start(mut self, air: Air) -> InboxHandler {
        let (tx, rx): (AsyncTx<_>, _) = spsc::build(spsc::List::new());

        air.handle.spawn(async move { loop {
            let identity = air.resolver.resolve(air.name, None).await;
            let home = *identity.servers().first().unwrap();
            let conn = air.purser.connect(home).await.unwrap();
            match conn.send(Request::Receive(Signed::new(&air.secret, (Compare::Greater, self.0)))).await.recv().await {
                Response::Inbox(received) => {
                    let home_identity = air.resolver.resolve(home, None).await;
                    for (signature, timestamp, data) in received {
                        if signature.verify(&home_identity, &[], Id::hash(&(air.name, timestamp, &data))).is_ok() && timestamp > self.0 {
                            self.0 = timestamp;
                            let data = postcard::from_bytes::<Encrypted>(&data).ok().and_then(|d| air.secret.decrypt(d).ok());
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

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn channel() {
        let secret = Secret::new();
        let key = secret.harden();
        let name = secret.name();

        let air = crate::Air::new(secret.clone());

        let (mut stream, sink) = Channel::new(key).start(air.clone(), secret);

        air.handle.block_on(async {
            let content = b"hello".to_vec();
            let rid = sink.write(content.clone()).await;
            let (timestamp, data) = stream.read().await;
            assert_eq!(stream.channel(), &Channel{key, index: 1, timestamp});
            assert_eq!(data, Event::Data(name, content.clone(), Some(rid)));

            let content2 = b"goodbye".to_vec();
            let rid = sink.write(content2.clone()).await;
            let (timestamp2, data2) = stream.read().await;
            assert_eq!(stream.channel(), &Channel{key, index: 2, timestamp: timestamp2});
            assert_eq!(data2, Event::Data(name, content2.clone(), Some(rid)));

            let write = tokio::spawn(async move {
                tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
                sink.write(b"late".to_vec()).await
            });

            let (_, data) = stream.read().await;
            assert_eq!(data, Event::Head);

            let rid = write.await.unwrap();

            let (_, data) = stream.read().await;
            assert_eq!(data, Event::Data(name, b"late".to_vec(), Some(rid)));
        });
    }
}
