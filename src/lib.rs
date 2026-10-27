use serde::{Serialize, Deserialize};

use std::collections::{HashMap, HashSet};

pub mod names;
pub use names::{
    Secret, Name, Id, Error, DefaultResolver, Identity, Resolver, Signature, Stream, StreamRequest,
    Signed, Sink, Drain,
};
pub use names::secp256k1::{PublicKey, Signature as KeySignature, Signed as KeySigned};

pub mod storage;
pub use storage::{Request, Response, Storage, DBRequest, DBResponse};

pub mod channel;
use channel::{Channel, Key};

pub mod contract;
pub use contract::{Contract, Metadata, Location, Instance, Output};

pub mod inbox;
use inbox::Inbox;

#[derive(Eq, PartialEq, Hash, Clone, Copy, Debug)]
pub enum RequestType {Storage, Inbox(inbox::RequestType)}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Air {
    secret: Secret,
    storage: Channel<Location>,
    locations: HashMap<Id, HashSet<Location>>,
    inbox: Inbox,
}
impl Air {
    pub fn new(secret: Secret) -> Result<Self, Error> {
        let key = Key::Secret(secret.set_path(&[Id::hash("INBOX")])?.harden(None)
            .derive(&[Id::hash("STORAGE")]));
        let storage = Channel::new(channel::Location {
            server: Name::orange_me(), discovery: key, encryption: key,
        });
        Ok(Self {inbox: Inbox::new(secret.clone())?, secret, storage, locations: HashMap::new()})
    }

    pub fn create<C: Contract>(&mut self, init: C::Init) -> Result<Instance<C>, Error> {
        let instance = Instance::new(self.secret.clone(), init)?;
        self.register(*instance.location());
        Ok(instance)
    }

    pub fn list(&self, contract: &Id) -> HashSet<Location> {
        self.locations.get(contract).cloned().unwrap_or_default()
    }

    pub async fn share<R: Resolver>(&mut self, resolver: &mut R, name: Name, location: Location) {
        self.inbox.send(resolver, name, location).await;
    }

    pub fn start(&mut self) -> HashMap<RequestType, Request> {
        let mut inbox: HashMap<_, _> = self.inbox.start().into_iter()
            .map(|(kind, request)| (RequestType::Inbox(kind), request)).collect();
        inbox.insert(RequestType::Storage, self.storage.start());
        inbox
    }

    pub fn requests(&mut self) -> HashMap<RequestType, Request> {
        let mut requests: HashMap<_, _> = self.inbox.requests().into_iter()
            .map(|(kind, request)| (RequestType::Inbox(kind), request)).collect();
        if let Some(request) = self.storage.request() {
            requests.insert(RequestType::Storage, request);
        }
        requests
    }

    pub async fn response<R: Resolver>(&mut self, resolver: &mut R, kind: RequestType, response: Response) -> Option<Location> {
        match kind {
            RequestType::Storage => {
                if let channel::Output::Read(_, location) = self.storage.response(response) {
                    return self.locations.entry(location.contract).or_default()
                        .insert(location).then_some(location)
                }
                None
            }
            RequestType::Inbox(kind) => {
                let (_, location) = self.inbox.response(resolver, kind, response).await?;
                self.register(location).then_some(location)
            }
        }
    }

    fn register(&mut self, location: Location) -> bool {
        if !self.locations.entry(location.contract).or_default().insert(location) {return false}
        self.storage.queue_mut().push_back(location);
        true
    }
}
