use serde::{Serialize, Deserialize};
use std::collections::{HashMap, HashSet};
use std::hash::Hash;
use std::fmt::Debug;
use crate::names::{Resolver, Secret, Name, Id, Error};
use crate::names::secp256k1::{SecretKey};
use crate::channel::{Channel, Location, Key, Output};
use crate::storage::{Request, Response};
use crate::contract;

#[derive(Eq, PartialEq, Hash, Clone, Copy, Debug)]
pub enum RequestType { Channel(Name), Notified, Notifying(Name), Notifications, }

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Inbox {
    secret: Secret,
    notified: (Channel<Name>, HashSet<Name>),
    channels: HashMap<Name, Channel<contract::Location>>,
    notifications: Channel<Name>,
    notifying: HashMap<Name, Channel<Name>>,
    locations: HashMap<Id, HashSet<contract::Location>>,
}
impl Inbox {
    pub fn new(secret: Secret) -> Result<Self, Error> {
        let secret = secret.set_path(&[Id::hash("INBOX")])?;
        let key = Key::Secret(secret.harden(None).derive(&[Id::hash("NOTIFIED")]));
        let notified = Location { server: Name::orange_me(), discovery: key, encryption: key };
        let notifications = Location {
            server: Name::orange_me(),
            discovery: Key::Secret(SecretKey::from_array(*Id::hash(&secret.name())).unwrap()),
            encryption: Key::Secret(secret.public(None).derive_risky(&[Id::hash("NOTIFICATIONS")])),
        };
        let key = Key::Secret(secret.harden(None).derive(&[Id::hash("STORAGE")]));
        let storage = Location { server: Name::orange_me(), discovery: key, encryption: key };
        Ok(Self {
            notified: (Channel::new(notified), HashSet::new()),
            channels: HashMap::from([(secret.name(), Channel::new(storage))]),
            notifications: Channel::new(notifications),
            notifying: HashMap::new(),
            locations: HashMap::new(),
            secret,
        })
    }

    pub fn list(&self, contract: &Id) -> HashSet<contract::Location> {
        self.locations.get(contract).cloned().unwrap_or_default()
    }

    pub async fn send<R: Resolver>(&mut self, resolver: &mut R, name: Name, location: contract::Location) -> bool {
        let channel = if name == self.secret.name() {
            if !self.locations.entry(location.contract).or_default().insert(location) {
                return false;
            }
            self.channels.get_mut(&name).unwrap()
        } else {
            let public =
                resolver.resolve(name, None).await.public().derive_risky(&[Id::hash("INBOX")]);
            if !self.notified.1.contains(&name) && !self.notifying.contains_key(&name) {
                let notifying = Location {
                    server: Name::orange_me(),
                    discovery: Key::Secret(SecretKey::from_array(*Id::hash(&name)).unwrap()),
                    encryption: Key::Public(public.derive_risky(&[Id::hash("NOTIFICATIONS")])),
                };
                let mut channel = Channel::new(notifying);
                channel.queue_mut().push_back(self.secret.name());
                self.notifying.insert(name, channel);
            }
            self.channels.entry(name).or_insert_with(|| {
                let key = self.secret.public(None).shared(&public, None);
                let location = Location {
                    server: Name::orange_me(),
                    discovery: Key::Secret(key),
                    encryption: Key::Secret(key),
                };
                Channel::new(location)
            })
        };
        channel.queue_mut().push_back(location);
        true
    }

    pub fn start(&mut self) -> HashMap<RequestType, Request> {
        let mut requests = HashMap::from([
            (RequestType::Notified, self.notified.0.start()),
            (RequestType::Notifications, self.notifications.start()),
        ]);
        requests
            .extend(self.channels.iter_mut().map(|(n, c)| (RequestType::Channel(*n), c.start())));
        requests.extend(
            self.notifying.iter_mut().map(|(n, c)| (RequestType::Notifying(*n), c.start())),
        );
        requests
    }

    pub fn requests(&mut self) -> HashMap<RequestType, Request> {
        let mut requests = HashMap::new();
        if let Some(request) = self.notified.0.request() {
            requests.insert(RequestType::Notified, request);
        }
        if let Some(request) = self.notifications.request() {
            requests.insert(RequestType::Notifications, request);
        }
        requests.extend(
            self.channels
                .iter_mut()
                .filter_map(|(n, c)| c.request().map(|r| (RequestType::Channel(*n), r))),
        );
        requests.extend(
            self.notifying
                .iter_mut()
                .filter_map(|(n, c)| c.request().map(|r| (RequestType::Notifying(*n), r))),
        );
        requests
    }

    pub async fn response<R: Resolver>(
        &mut self, resolver: &mut R, request_type: RequestType, response: Response,
    ) -> Option<(Name, contract::Location)> {
        match request_type {
            RequestType::Notified => match self.notified.0.response(response) {
                Output::Created(_, _) => {}
                Output::Read(_, name) => {
                    self.notified.1.insert(name);
                    self.notifying.remove(&name);
                    self.process_notification(resolver, name).await;
                }
                Output::Subscribed => {}
                Output::Garbage => {}
            },
            RequestType::Notifications => match self.notifications.response(response) {
                Output::Created(_, name) | Output::Read(_, name) => {
                    self.notified.0.queue_mut().push_back(name);
                    self.notified.1.insert(name);
                    self.notifying.remove(&name);
                    self.process_notification(resolver, name).await;
                }
                Output::Subscribed => {}
                Output::Garbage => {}
            },
            RequestType::Channel(name) => {
                let channel = self.channels.get_mut(&name).unwrap();
                match channel.response(response) {
                    Output::Created(_, _location) => {}
                    Output::Read(_, location) => {
                        return self
                            .locations
                            .entry(location.contract)
                            .or_default()
                            .insert(location)
                            .then_some((name, location));
                    }
                    Output::Subscribed => {}
                    Output::Garbage => {}
                }
            }
            RequestType::Notifying(name) => {
                if let Some(channel) = self.notifying.get_mut(&name) {
                    match channel.response(response) {
                        Output::Created(_, _) => {
                            self.notified.0.queue_mut().push_back(name);
                            self.notified.1.insert(name);
                            self.notifying.remove(&name);
                        }
                        Output::Read(_, _) => {}
                        Output::Subscribed => {}
                        Output::Garbage => {}
                    }
                }
            }
        }
        None
    }

    pub async fn process_notification<R: Resolver>(&mut self, resolver: &mut R, name: Name) {
        if !self.channels.contains_key(&name) {
            let public =
                resolver.resolve(name, None).await.public().derive_risky(&[Id::hash("INBOX")]);
            let key = self.secret.public(None).shared(&public, None);
            let location = Location {
                server: Name::orange_me(),
                discovery: Key::Secret(key),
                encryption: Key::Secret(key),
            };
            self.channels.insert(name, Channel::new(location));
        }
    }
}
