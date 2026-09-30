use crate::names::{Secret, Signature, Signed, Name, Id, Resolver, Error};
use crate::names::secp256k1::{Signed as KeySigned, SecretKey, PublicKey, Encrypted as KeyEncrypted};
use crate::storage::{Request, Response};

use serde::{Serialize, Deserialize};

use std::collections::VecDeque;
use std::hash::Hash;
use std::fmt::Debug;

#[derive(Serialize, Deserialize, Hash, Debug, Clone, Eq, PartialEq)]
pub struct Location {
    pub server: Name,
    pub path: Vec<Id>,
    pub key: SecretKey,
}

#[derive(Clone, Debug, PartialEq)]
pub enum Output<M> { 
    Created(u64, Name, M),
    Read(u64, Name, M),
    Garbage,
    Subscribed,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
enum State {
    #[default] WaitingToMakeRequest,
    Creating,
    Reading,
    Subscribed,
}

enum Outgoing<M> {
    Create(SecretKey, M, Id, Name),
    Read(SecretKey, bool),
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Channel<M> {
    location: Location,
    timestamp: u64,
    index: u64,
    queue: VecDeque<M>,
    outgoing: Option<Outgoing<M>>,

    previous_state: State
}
impl<M: Serialize + for<'a> Deserialize<'a> + Debug> Channel<M> {
    pub fn new(location: Location) -> Self {Channel{
        location, timestamp: 0, index: 0, queue: VecDeque::new(), outgoing: None, response: None, previous_state: State::Init
    }}

    //Model Reading
    pub fn location(&self) -> &Location {&self.location}
    pub fn timestamp(&self) -> u64 {self.timestamp}
    pub fn is_subscribed(&self) -> bool {matches!(self.state, State::Subscribed(_))}
    pub fn outgoing(&self) -> Option<&M> {match &self.outgoing {Some(Outgoing::Create(_, m, _, _)) => Some(m), _ => None}}
    pub fn all(&self) -> Vec<&M> {
        let mut vec = self.outgoing().map(|m| vec![m]).unwrap_or_default();
        vec.extend(self.queue.iter());
        vec
    }
    //Model Reading
    
    //Model Writing
    pub fn queue(&mut self) -> &mut VecDeque<M> {&mut self.queue}
    pub fn request(&mut self, secret: &Secret) -> Result<Request, Error> {
        match self.outgoing.take() {
            Outgoing::Read(_, _) => {
                self.queue.pop_front().map(|m| self.create_request(secret, m)).unwrap_or_else(|| Ok(self.read_request()))
            },
            Outgoing::Create(_, message, _, _) => {
                self.create_request(secret, message)
            },
        }
    }
    
    pub async fn response<R: Resolver>(&mut self, resolver: &mut R, response: Response) -> Output<M> {
        match (self.outgoing.take(), response) {
            (Some(Outgoing::Create(sec, message, hash, name)), Response::Created(sig, time)) => {
                self.verify(resolver, sec.public_key(), sig, time, Some(hash)).await.expect("Bad Air Server");
                Output::Created(time, name, message)
            },
            (Some(Outgoing::Read(sec, false)), Response::Read(sig, time, None)) => {
                self.verify(resolver, sec.public_key(), sig, time, None).await.expect("Bad Air Server");
                self.outgoing = Some(Outgoing::Read(sec, true));
                Output::Subscribed
            },
            (Some(outgoing), Response::Read(sig, time, Some((key_sig, payload)))) => {
                let hash = Id::hash(&payload);
                let (sec, creating) = match outgoing {
                    Outgoing::Create(sec, message, h, name) if h == hash => (sec, Some((name, message))),
                    Outgoing::Create(sec, _, _, _) => {
                        self.queue.push_front(message); (sec, None)
                    },
                    Outgoing::Read(sec, _) => (sec, None),
                };
                let key = sec.public_key();
                self.verify(resolver, key, sig, time, Some(hash)).await.expect("Bad Air Server");
                if let Some((name, message)) = creating {
                    Output::Created(time, name, message)
                } else {
                    if key.verify(&key_sig, hash).is_ok()
                    && let Some(signed) = postcard::from_bytes::<KeyEncrypted>(&payload).ok().and_then(|e|
                        sec.decrypt(e).ok().and_then(|d| postcard::from_bytes::<Signed<Vec<u8>>>(&d).ok())
                    ) {
                        let identity = resolver.resolve(signed.signer, Some(time)).await;
                        if signed.verify(&identity, &self.location.path).is_ok()
                        && let Ok(payload) = postcard::from_bytes::<M>(&signed.payload) {
                            return Output::Read(time, signed.signer, payload);
                        }
                    }
                    Output::Garbage
                }
            },
            s => panic!("invalid outgoing/response: {s:?}")
        }
    }
    //Model Writing

    //State Functions
    pub fn evaluate(&self) -> State {
        if self.response.is_some() {
            State::ProcessingResponse
        } else {match (self.outgoing, self.response) {
            None => State::WaitingToMakeRequest,
            Some(Outgoing::Create(_, _, _, _)) => State::Creating,
            Some(Outgoing::Read(_, false)) => State::Reading,
            Some(Outgoing::Read(_, true)) => State::Subscribed,
        }}
    }

    pub fn validate(prev: &State, next: &State) -> bool {
        match (prev, next) {
            (State::WaitingToMakeRequest, State::Reading) => true,
            (State::WaitingToMakeRequest, State::Creating) => true,
            (State::Reading, State::Subscribed) => true,
            (State::Reading, State::WaitingToMakeRequest) => true,
            (State::Subscribed, State::WaitingToMakeRequest) => true,
            (State::Subscribed, State::Creating) => true,
            (State::Creating, State::WaitingToMakeRequest) => true,
            _ => false
        }
    }
    pub fn step(&mut self) -> SideEffect<M> {
        let state = Self::evaluate();
        if !validate(&self.previous_state, &state) {panic!("Invalid State");}
        let side_effect = match (self.previous_state, &state) {

        };
        self.previous_state = state;
        side_effect
    }
    //State Functions

    //Helper Functions to Model Writers
    async fn verify<R: Resolver>(&mut self, resolver: &mut R, key: PublicKey, sig: Signature, time: u64, hash: Option<Id>) -> Result<bool, Error> {
        let identity = resolver.resolve(self.location.server, Some(time)).await;
        sig.verify(&identity, &[], Id::hash(&(key, time, hash.unwrap_or(Id::MIN))))?;
        if hash.is_some() {self.index += 1;}
        Ok(if time > self.timestamp { self.timestamp = time; true } else {false})
    }

    fn read_request(&mut self) -> Request {
        let key = self.location.key.derive(&[Id::hash(&self.location.server)]).derive(&[Id::hash(&self.index)]);
        self.outgoing = Some(Outgoing::Read(key, false));
        Request::Read(key.public_key())
    }

    fn create_request(&mut self, secret: &Secret, outgoing: M) -> Result<Request, Error> {
        let key = self.location.key.derive(&[Id::hash(&self.location.server)]).derive(&[Id::hash(&self.index)]);
        let secret = secret.set_path(&self.location.path)?;
        let signed = postcard::to_allocvec(&Signed::new(&secret, postcard::to_allocvec(&outgoing).unwrap())).unwrap();
        let encrypted = postcard::to_allocvec(&key.public_key().encrypt(signed)).unwrap();
        self.outgoing = Some(Outgoing::Create(key, outgoing, Id::hash(&encrypted), secret.name()));
        Ok(Request::Create(KeySigned::new(&key, encrypted)))
    }
    //Help Functions to Model Writers
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::names::DefaultResolver;
    use crate::websocket::Socket;

    #[tokio::test]
    async fn test() {
        let secret = Secret::new();
        let location = Location{
            key: secret.harden(),
            path: Vec::new(),
            server: Name::orange_me()
        };
        let mut channel = Channel::new(location);
        let mut resolver = DefaultResolver::start();
        let mut socket = Socket::connect(&mut resolver, Name::orange_me()).await;

        let mut make_rr = async |r: Request| {
            socket.0.write(None, postcard::to_allocvec(&r).unwrap()).await;
            postcard::from_bytes::<Response>(&socket.1.read().await.1).unwrap()
        };

        let request = channel.request(&secret).unwrap();
        let response = make_rr(request).await;
        assert_eq!(Output::<String>::Subscribed, channel.response(&mut resolver, response).await);

        channel.queue().push_back("Hello".to_string());

        let request = channel.request(&secret).unwrap();
        let response = make_rr(request).await;
        let Output::Created(_, name, msg) = channel.response(&mut resolver, response).await else {panic!("_");};

        assert_eq!(name, secret.name());
        assert_eq!(msg, "Hello".to_string());
        assert!(matches!(channel.request(&secret), Ok(Request::Read(_))));
    }
}
