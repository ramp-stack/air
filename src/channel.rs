use serde::{Serialize, Deserialize};

use crate::names::{secp256k1::{Signed as KeySigned, SecretKey, Encrypted as KeyEncrypted}, Resolver, Signed, Secret, Name, Id, now};
use crate::{Purser, Request, Response};

use std::collections::BTreeMap;

use crossfire::{MAsyncTx, AsyncTx, AsyncRx, MTx, mpsc, spsc};
use tokio::spawn;

pub const CHANNEL: &str = "CHANNEL";

#[derive(Debug)]
pub struct Stream(Channel, AsyncRx<spsc::List<(Channel, Option<(Name, Vec<u8>)>)>>);
impl Stream {
    pub fn channel(&self) -> &Channel {&self.0}
    pub async fn read(&mut self) -> (u64, Option<(Name, Vec<u8>)>) {
        let (channel, data) = self.1.recv().await.unwrap();
        self.0 = channel;
        (self.0.timestamp, data)
    }

    pub async fn read_all(&mut self) -> BTreeMap<u64, (Name, Vec<u8>)> {
        let mut results = BTreeMap::new();
        while let Ok((channel, data)) = self.1.try_recv() {
            self.0 = channel;
            if let Some(data) = data {
                results.insert(self.0.timestamp, data);
            }
        }
        results
    }
}

#[derive(Clone, Debug)]
pub struct Sink(MAsyncTx<spsc::List<Vec<u8>>>);
impl Sink {
    pub async fn write(&self, data: Vec<u8>) {self.0.send(data).await.unwrap()}
    pub fn write_sync(&self, data: Vec<u8>) {MTx::from(self.0.clone()).send(data).unwrap()}
}

///A Channel Handle is not Clone but the Sink returned from .split() is.
#[derive(Debug)]
pub struct Handle(Stream, Sink);
impl Handle {
    pub fn split(self) -> (Stream, Sink) {(self.0, self.1)}
    pub fn channel(&self) -> &Channel {self.0.channel()}
    pub async fn write(&mut self, data: Vec<u8>) {self.1.write(data).await}
    pub async fn read(&mut self) -> (u64, Option<(Name, Vec<u8>)>) {self.0.read().await}
    pub async fn read_all(&mut self) -> BTreeMap<u64, (Name, Vec<u8>)> {self.0.read_all().await}
}

//I need a channel type similar to a set where I read all the entries before I try to write a new
//entry to insure at most only one instance of an item exists in the channel.
//This would be used for storage purposes, keeping track of contracts or instances/locations.

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
    pub fn start(mut self, mut resolver: Resolver, purser: Purser, secret: &Secret) -> Handle {
        let secret = secret.derive(&[Id::hash(CHANNEL)]);
        let (write, rx): (MAsyncTx<_>, AsyncRx<_>) = mpsc::build(mpsc::List::new());
        let (tx, read): (AsyncTx<_>, AsyncRx<_>) = spsc::build(spsc::List::new());

        let channel = self;
        spawn(async move {
            let server = Name::orange_me();
            let key = self.key.derive(&[Id::hash(&server)]);
            let connection = purser.connect(server).await.unwrap();

            let mut request: Option<(Vec<u8>, Vec<u8>)> = None;
            loop {
                let key = key.derive(&[Id::hash(&self.index)]);
                let public = key.public_key();
                match &mut request {
                    Some(_) => {},
                    none => {*none = rx.try_recv().ok().map(|d: Vec<u8>|
                        (d.clone(), postcard::to_allocvec(&Signed::new(&secret, d)).unwrap())
                    );}
                }

                if let Some((signature, time, key_sig, payload)) = match request.as_ref() {
                    Some((_, data)) => {
                        let encrypted = postcard::to_allocvec(&public.encrypt(data.clone())).unwrap();
                        let hash = Id::hash(&encrypted);
                        let response = connection.send(Request::Create(KeySigned::new(&key, encrypted))).await;
                        match response{
                            Response::Create(signature, time) => {
                                let identity = resolver.resolve(server, Some(time)).await;
                                if signature.verify(&identity, &[], Id::hash(&(public, time, hash))).is_ok() 
                                && self.timestamp < time && time < now() {
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
                    let identity = resolver.resolve(server, Some(time)).await;
                    if signature.verify(&identity, &[], Id::hash(&(public, time, hash))).is_ok()
                    && key_sig.verify(&public, hash).is_ok() {
                        let result = if time > self.timestamp {
                            self.timestamp = time;
                            if let Some(signed) = postcard::from_bytes::<KeyEncrypted>(&payload).ok().and_then(|e| key.decrypt(e).ok().and_then(|d| postcard::from_bytes::<Signed<Vec<u8>>>(&d).ok())) {
                                let identity = resolver.resolve(signed.signer, Some(time)).await;
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
        Handle(Stream(channel, read), Sink(write))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[tokio::test]
    async fn channel() {
        let secret = Secret::new();
        let key = secret.harden();
        let name = secret.name();

        let resolver = Resolver::start();
        let purser = Purser::start(resolver.clone());
        let mut handle = Channel::new(key).start(resolver.clone(), purser.clone(), &secret);

        let content = b"hello".to_vec();
        handle.write(content.clone()).await;
        let (timestamp, data) = handle.read().await;
        assert_eq!(handle.channel(), &Channel{key, index: 1, timestamp});
        assert_eq!(data, Some((name, content.clone())));

        let content2 = b"goodbye".to_vec();
        handle.write(content2.clone()).await;
        let (timestamp2, data2) = handle.read().await;
        assert_eq!(handle.channel(), &Channel{key, index: 2, timestamp: timestamp2});
        assert_eq!(data2, Some((name, content2.clone())));

        let mut handle = Channel::new(key).start(resolver, purser, &secret);
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        let r = handle.read_all().await;
        assert_eq!(r, BTreeMap::from([(timestamp, (name, content)), (timestamp2, (name, content2))]));
    }
}
