use crate::names::{Resolver, Secret, Name, Id, now, Error};
use crate::names::secp256k1::{SecretKey};
use crate::channel::{self, Channel, Location, Key, Output};
use crate::storage::{Request, Response};
use crate::contract::{self, Contract, Instance};

use std::collections::{HashMap, HashSet};
use std::hash::Hash;
use std::ops::Deref;
use std::fmt::Debug;

use serde::{Serialize, Deserialize};

const INBOX: &str = "INBOX";
const NOTIFIED: &str = "NOTIFIED";
const NOTIFICATIONS: &str = "NOTIFICATIONS";

#[derive(Eq, PartialEq, Hash, Clone, Copy, Debug)]
pub enum RequestType {
    Channel(Name),
    Notified,
    Notifying(Name),
    Notifications
}

pub struct Inbox {
    secret: Secret,
    notified: (Channel<Name>, HashSet<Name>),
    channels: HashMap<Name, Channel<(Id, contract::Location)>>,
    notifications: Channel<Name>,
    notifying: HashMap<Name, Channel<Name>>,
}
impl Inbox {
    pub fn new(secret: Secret) -> Result<Self, Error> {
        let secret = secret.set_path(&[Id::hash(INBOX)])?;
        let key = Key::Secret(secret.harden(None).derive(&[Id::hash(NOTIFIED)]));
        let notified = Location{server: Name::orange_me(), discovery: key, encryption: key};
        let notifications = Location{
            server: Name::orange_me(),
            discovery: Key::Secret(SecretKey::from_array(*Id::hash(&secret.name())).unwrap()),
            encryption: Key::Secret(secret.public(None).derive_risky(&[Id::hash(NOTIFICATIONS)]))
        };
        Ok(Self {
            secret,
            notified: (Channel::new(notified), HashSet::new()),
            channels: HashMap::new(),
            notifications: Channel::new(notifications),
            notifying: HashMap::new()
        })
    }

    pub fn start(&mut self) -> HashMap<RequestType, Request> {
        let mut requests = HashMap::from([
            (RequestType::Notified, self.notified.0.start()),
            (RequestType::Notifications, self.notifications.start()),
        ]);
        requests.extend(self.channels.iter_mut().map(|(n, c)| (RequestType::Channel(*n), c.start())));
        requests.extend(self.notifying.iter_mut().map(|(n, c)| (RequestType::Notifying(*n), c.start())));
        requests
    }

    pub async fn send<R: Resolver>(&mut self, resolver: &mut R, name: Name, location: contract::Location) {
        let public = resolver.resolve(name, None).await.public().derive_risky(&[Id::hash(INBOX)]);
        if !self.notified.1.contains(&name) && !self.notifying.contains_key(&name) {
            let notifying = Location{
                server: Name::orange_me(),
                discovery: Key::Secret(SecretKey::from_array(*Id::hash(&name)).unwrap()),
                encryption: Key::Public(public.derive_risky(&[Id::hash(NOTIFICATIONS)]))
            };
            let mut channel = Channel::new(notifying);
            channel.queue_mut().push_back(self.secret.name());
            self.notifying.insert(name, channel);
        }
        let channel = self.channels.entry(name).or_insert_with(|| {
            let key = self.secret.public(None).shared(&public, None);
            let location = Location{
                server: Name::orange_me(),
                discovery: Key::Secret(key),
                encryption: Key::Secret(key)
            };
            Channel::new(location)
        });
        channel.queue_mut().push_back((C::id(), location));
    }

    pub fn requests(&mut self) -> HashMap<RequestType, Request> {
        let mut requests = HashMap::new();
        if let Some(request) = self.notified.0.request() {
            requests.insert(RequestType::Notified, request);
        }
        if let Some(request) = self.notifications.request() {
            requests.insert(RequestType::Notifications, request);
        }
        requests.extend(self.channels.iter_mut().filter_map(|(n, c)| c.request().map(|r| (RequestType::Channel(*n), r))));
        requests.extend(self.notifying.iter_mut().filter_map(|(n, c)| c.request().map(|r| (RequestType::Notifying(*n), r))));
        requests
    }

    pub async fn response<R: Resolver>(&mut self, resolver: &mut R, request_type: RequestType, response: Response) -> Option<(Name, (Id, contract::Location))> {
        match request_type {
            RequestType::Notified => match self.notified.0.response(response) {
                Output::Created(_, _) => {},
                Output::Read(_, name) => {
                    self.notified.1.insert(name);
                    self.notifying.remove(&name);
                    self.process_notification(resolver, name).await;
                }
                Output::Subscribed => {},
                Output::Garbage => {}
            },
            RequestType::Notifications => match self.notifications.response(response) {
                Output::Created(_, name) | Output::Read(_, name) => {
                    self.notified.0.queue_mut().push_back(name);
                    self.notified.1.insert(name);
                    self.notifying.remove(&name);
                    self.process_notification(resolver, name).await;
                }
                Output::Subscribed => {},
                Output::Garbage => {}
            },
            RequestType::Channel(name) => {
                let channel = self.channels.get_mut(&name).unwrap();
                match channel.response(response) {
                    Output::Created(_, _location) => {},
                    Output::Read(_, location) => {return Some((name, location));},
                    Output::Subscribed => {},
                    Output::Garbage => {}
                }
            },
            RequestType::Notifying(name) => {
                if let Some(channel) = self.notifying.get_mut(&name) {
                    match channel.response(response) {
                        Output::Created(_, _) => {
                            self.notified.0.queue_mut().push_back(name);
                            self.notified.1.insert(name);
                            self.notifying.remove(&name);
                        },
                        Output::Read(_, _) => {},
                        Output::Subscribed => {},
                        Output::Garbage => {}
                    }
                }
            }
        }
        None
    }

    pub async fn process_notification<R: Resolver>(&mut self, resolver: &mut R, name: Name) {
        if !self.channels.contains_key(&name) {
            let public = resolver.resolve(name, None).await.public().derive_risky(&[Id::hash(INBOX)]);
            let key = self.secret.public(None).shared(&public, None);
            let location = Location{
                server: Name::orange_me(),
                discovery: Key::Secret(key),
                encryption: Key::Secret(key)
            };
            self.channels.insert(name, Channel::new(location));
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::names::DefaultResolver;
    use crate::client::Client;
    use crate::contract::{Instance, Metadata, Contract};

    #[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Hash)]
    pub struct Message {
        author: Name,
        //timestamp: u64,
        body: String,
        sent: bool
    }

    #[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Hash)]
    pub struct Room {
        author: Name,
        name: String,
        messages: Vec<Message>
    }
    impl Contract for Room {
        type Init = String;
        type Message = String;
        type Result = usize;

        fn id() -> Id {Id::hash("ROOM")}

        fn init(init: Self::Init, metadata: Metadata) -> Self {
            Room{
                author: metadata.signer,
                name: init,
                messages: vec![]
            }
        }

        fn apply(&mut self, message: Self::Message, metadata: Metadata) -> Self::Result {
            self.messages.push(Message{
                body: message,
                author: metadata.signer,
                sent: metadata.confirmed
            });
            self.messages.len()
        }
    }

    #[tokio::test]
    async fn test() {
        let alice = Secret::new();
        let bob = Secret::new();
        println!("alice: {}", alice.name());
        println!("bob: {}", bob.name());

        let mut a_client = Client::new(DefaultResolver::start()).await;
        let mut b_client = Client::new(DefaultResolver::start()).await;
        let mut resolver = DefaultResolver::start();

        let mut awaiting = HashMap::new();
        let mut make_requests = async |inbox: &mut Inbox, name: Name, init: bool| {
            let mut resolver = DefaultResolver::start();
            let client = if name == alice.name() {&mut a_client} else {&mut b_client};
            let awaiting = awaiting.entry(name).or_insert(HashMap::new());
            let mut locations = vec![]; 
            let requests = if init {inbox.start()} else {inbox.requests()};
            for (ty, req) in requests {
                awaiting.insert(ty, client.send(req).await);
            }
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
            for (key, responder) in awaiting {
                match responder.try_recv() {
                    Ok(response) => {
                        if let Some(p) = inbox.response(&mut resolver, *key, response).await {
                            locations.push(p);
                        }
                    },
                    Err(e) => println!("{:?}, {:?}", key, e),
                }
            }

            locations
        };


        let mut a_inbox = Inbox::new(alice.clone()).unwrap();
        let mut b_inbox = Inbox::new(bob.clone()).unwrap();
        make_requests(&mut a_inbox, alice.name(), true).await;
        make_requests(&mut b_inbox, bob.name(), true).await;
        let mut a_room = Instance::<Room>::new(alice.clone(), "MyRoom".to_string()).unwrap();

        a_inbox.send(&mut resolver, bob.name(), &a_room).await;
        assert_eq!(a_inbox.notifying.get(&bob.name()).unwrap().location(), b_inbox.notifications.location());
        //Status: channel with bob has a queued location, notifying bob has alices name queued
        make_requests(&mut a_inbox, alice.name(), false).await;

        assert!(a_inbox.channels.get(&bob.name()).unwrap().queue().is_empty());//location was sent
        assert!(a_inbox.notifying.is_empty());
        assert!(a_inbox.notified.1.contains(&bob.name()));
        assert!(a_inbox.notified.0.queue_mut().len() == 1);

        make_requests(&mut a_inbox, alice.name(), false).await;
        assert!(a_inbox.notified.1.contains(&bob.name()));
        assert!(a_inbox.notified.0.queue().is_empty());

        make_requests(&mut b_inbox, bob.name(), false).await;
        assert!(b_inbox.channels.get(&alice.name()).unwrap().queue().is_empty());
        assert!(b_inbox.notifying.is_empty());
        assert!(b_inbox.notified.1.contains(&alice.name()));
        assert!(b_inbox.notified.0.queue_mut().len() == 1);

        assert_eq!(make_requests(&mut b_inbox, bob.name(), false).await, vec![(alice.name(), (Room::id(), *a_room.location()))]);
    }
}
