use crate::names::{Name, Id};
use crate::names::secp256k1::{Signed as KeySigned, Signature as KeySignature, SecretKey, PublicKey};
use crate::storage::{Request, Response};

use serde::{Serialize, Deserialize};

use std::collections::VecDeque;
use std::hash::Hash;
use std::fmt::Debug;

#[derive(Serialize, Deserialize, Hash, Debug, Clone, Copy, Eq)]
pub enum Key {Secret(SecretKey), Public(PublicKey)}
impl Key {
    pub fn public(&self) -> PublicKey {match self {
        Key::Secret(s) => s.public_key(),
        Key::Public(p) => *p
    }}
    pub fn secret(&self) -> Option<SecretKey> {match self {
        Key::Secret(s) => Some(*s),
        Key::Public(_) => None
    }}
}
impl PartialEq for Key {
    fn eq(&self, other: &Self) -> bool {
        self.public() == other.public()
    }
}

#[derive(Serialize, Deserialize, Hash, Debug, Clone, Copy, Eq, PartialEq)]
pub struct Location {
    pub server: Name,
    pub discovery: Key,
    pub encryption: Key
}

impl Location {
    fn discovery(&self, index: u64) -> PublicKey {
        self.discovery.public().derive_risky(&[Id::hash(&self.server), Id::hash(&self.encryption.public()), Id::hash(&index)])
    }

    fn writing(&self, index: u64) -> Option<SecretKey> {
        self.discovery.secret().map(|s| s.derive_risky(&[Id::hash(&self.server), Id::hash(&self.encryption.public()), Id::hash(&index)]))
    }

    fn encryption(&self, index: u64) -> PublicKey {
        self.encryption.public().derive_risky(&[Id::hash(&self.server), Id::hash(&self.discovery.public()), Id::hash(&index)])
    }

    fn decryption(&self, index: u64) -> Option<SecretKey> {
        self.encryption.secret().map(|s| s.derive_risky(&[Id::hash(&self.server), Id::hash(&self.discovery.public()), Id::hash(&index)]))
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum Output<M> { 
    Created(u64, M),
    Read(u64, M),
    Subscribed,
    Garbage,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
enum Outgoing<M> { Create(Id, M), Read(bool) }

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Channel<M> {
    location: Location,
    timestamp: u64,
    index: u64,
    queue: VecDeque<M>,
    outgoing: Option<Outgoing<M>>,
}
impl<M: Serialize + for<'a> Deserialize<'a> + Debug> Channel<M> {
    pub fn new(location: Location) -> Self {Channel{
        location, timestamp: 0, index: 0, queue: VecDeque::new(), outgoing: None
    }}

    pub fn location(&self) -> &Location {&self.location}
    pub fn timestamp(&self) -> u64 {self.timestamp}
    pub fn is_subscribed(&self) -> bool {matches!(self.outgoing, Some(Outgoing::Read(true)))}
    pub fn outgoing(&self) -> Option<&M> {match &self.outgoing {Some(Outgoing::Create(_, m)) => Some(m), _ => None}}
    pub fn queue(&self) -> &VecDeque<M> {&self.queue}

    pub fn queue_mut(&mut self) -> &mut VecDeque<M> {&mut self.queue}

    pub fn start(&mut self) -> Request {
        if let Some(Outgoing::Create(_, m)) = self.outgoing.take() {self.request_create(m)} else {self.request().unwrap()}
    }

    pub fn request(&mut self) -> Option<Request> {
        if matches!(self.outgoing, Some(Outgoing::Create(_, _))) 
        || (self.outgoing.is_some() && self.queue.is_empty()) {None} else {
            if !self.queue.is_empty() && matches!(self.location.discovery, Key::Secret(_)) {
                let m = self.queue.pop_front().unwrap();
                Some(self.request_create(m))
            } else {
                Some(self.request_read())
            }
        }
    }

    pub fn response(&mut self, response: Response) -> Output<M> {
        match (self.outgoing.take(), response) {
            (Some(Outgoing::Create(hash, m)), Response::Created(time)) if self.verify(time, Some((None, hash))) =>
                Output::Created(time, m),
            (Some(Outgoing::Read(_)), Response::Read(time, None)) if self.verify(time, None) => {
                self.outgoing = Some(Outgoing::Read(true));
                Output::Subscribed
            },
            (Some(Outgoing::Create(h, m)), Response::Read(time, Some((key_sig, payload)))) => {
                let hash = Id::hash(&payload);
                let read_created = h == hash;
                let key_sig = (!read_created).then_some(key_sig);//skip key_sig verification if I created it
                match (read_created, self.verify(time, Some((key_sig, hash)))) {
                    (true, true) => Output::Created(time, m),
                    (false, true) => {
                        self.queue.push_front(m);
                        self.decrypt(time, payload)
                    },
                    (_, false) => {
                        self.queue.push_front(m);
                        println!("Garbage 2");
                        Output::Garbage
                    },
                }
            },
            (Some(Outgoing::Read(_)), Response::Read(time, Some((key_sig, payload))))
                if self.verify(time, Some((Some(key_sig), Id::hash(&payload)))) =>
                    self.decrypt(time, payload),
            _ => Output::Garbage
        }
    }

    //Note Decrypt is always called after Verify which increases the key index hence index-1
    fn decrypt(&self, time: u64, payload: Vec<u8>) -> Output<M> {
        if let Some(decryption) = self.location.decryption(self.index-1)
        && let Some(payload) = decryption.decrypt(payload).ok().and_then(|m| postcard::from_bytes(&m).ok()) {
            return Output::Read(time, payload);
        }
        Output::Garbage
    }

    fn verify(&mut self, time: u64, key_sig: Option<(Option<KeySignature>, Id)>) -> bool {
        let key = self.location.discovery(self.index);
        if let Some((Some(key_sig), hash)) = key_sig && key.verify(&key_sig, hash).is_err() {panic!("Bad Air Server");}
        if key_sig.is_some() {self.index += 1;}
        if time > self.timestamp { self.timestamp = time; true } else {false}
    }

    fn request_read(&mut self) -> Request {
        let key = self.location.discovery(self.index);
        self.outgoing = Some(Outgoing::Read(false));
        Request::Read(key)
    }

    fn request_create(&mut self, outgoing: M) -> Request {
        let key = self.location.writing(self.index).unwrap();
        let encryption = self.location.encryption(self.index);
        let encrypted = encryption.encrypt(postcard::to_allocvec(&outgoing).unwrap());
        self.outgoing = Some(Outgoing::Create(Id::hash(&encrypted), outgoing));
        Request::Create(KeySigned::new(&key, encrypted))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::names::DefaultResolver;
    use crate::client::Client;

    #[tokio::test]
    async fn test() {
        let location = Location{
            server: Name::orange_me(),
            discovery: Key::Secret(SecretKey::new()),
            encryption: Key::Secret(SecretKey::new()),
        };
        let mut a_channel = Channel::new(location);
        let mut a_client = Client::new(DefaultResolver::start()).await;

        let response = a_client.send(a_channel.request().unwrap()).await.recv().await.unwrap();
        assert_eq!(Output::Subscribed, a_channel.response(response));

        let m = "Hello".to_string();
        a_channel.queue_mut().push_back(m.clone());
        let response = a_client.send(a_channel.request().unwrap()).await.recv().await.unwrap();
        let Output::Created(time, msg) = a_channel.response(response) else {panic!("_");};
        assert_eq!(m, msg);

        let mut responder = a_client.send(a_channel.request().unwrap()).await;
        let response = responder.recv().await.unwrap();
        assert_eq!(Output::Subscribed, a_channel.response(response));

        let mut b_channel = Channel::new(location);
        let mut b_client = Client::new(DefaultResolver::start()).await;

        let response = b_client.send(b_channel.request().unwrap()).await.recv().await.unwrap();
        let Output::Read(rt, rm) = b_channel.response(response) else {panic!("_");};
        assert_eq!(rt, time);
        assert_eq!(rm, m);

        let response = b_client.send(b_channel.request().unwrap()).await.recv().await.unwrap();
        assert_eq!(Output::Subscribed, b_channel.response(response));

        let m = "Hi".to_string();
        b_channel.queue_mut().push_back(m.clone());
        let response = b_client.send(b_channel.request().unwrap()).await.recv().await.unwrap();
        let Output::Created(time, msg) = b_channel.response(response) else {panic!("_");};
        assert_eq!(m, msg);

        let response = responder.recv_timeout(std::time::Duration::from_millis(100)).await.unwrap();
        let Output::Read(rt, rm) = a_channel.response(response) else {panic!("_");};
        assert_eq!(rt, time);
        assert_eq!(rm, m);
    }
}
