use crate::names::{Resolver, Secret, Signed, Name, Id, now, Error};
use crate::names::secp256k1::SecretKey;
use crate::channel::{self, Channel, Key};
use crate::storage::{Request, Response};

use std::hash::Hash;
use std::fmt::Debug;

use serde::{Serialize, Deserialize};

#[derive(Clone, Debug, PartialEq)]
pub enum Output<R> { 
    Init(Vec<R>),
    Created(R, Vec<R>),
    Read(R, Vec<R>),
    Subscribed,
    Garbage,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Hash, Copy)]
pub struct Location {
    pub server: Name,
    pub key: SecretKey,
    pub contract: Id,
    pub instance: Id
}

pub struct Metadata {
    pub signer: Name,
    pub timestamp: u64,
    pub confirmed: bool
}
impl Metadata {
    fn pending(signer: Name) -> Self {Metadata{signer, timestamp: now(), confirmed: false}}
    fn confirmed(signer: Name, timestamp: u64) -> Self {Metadata{signer, timestamp, confirmed: true}}
}

pub trait Contract: Serialize + for<'a> Deserialize<'a> + Hash + Clone + Debug + Send + Sync + 'static {
    type Message: Serialize + for<'a> Deserialize<'a> + Hash + Clone + Debug + Send + Sync;
    type Init: Serialize + for<'a> Deserialize<'a> + Hash + Clone + Debug + Send + Sync;

    type Result: Clone + Debug + Send + Sync;
    
    fn id() -> Id;

    fn init(init: Self::Init, metadata: Metadata) -> Self;

    fn apply(&mut self, message: Self::Message, metadata: Metadata) -> Self::Result;
}

#[derive(Serialize, Deserialize, Debug, Clone, Hash)]
enum Message<C: Contract> {Init(C::Init), Message(C::Message)}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(bound = "C: Contract")]
pub struct Instance<C: Contract> {
    secret: Secret,
    channel: Channel<Signed<Message<C>>>,
    location: Location,
    confirmed: Option<C>,
    pending: Option<C>,
}
impl<C: Contract> Instance<C> {
    pub fn generate_location(secret: &Secret, init: &C::Init) -> Result<Location, Error> {
        let instance = Id::hash(&(&init, secret.name()));
        let key = secret.set_path(&[C::id(), instance])?.harden(None);
        Ok(Location{server: Name::orange_me(), key, contract: C::id(), instance})
    }

    pub fn new(secret: Secret, init: C::Init) -> Result<Self, Error> {
        let location = Self::generate_location(&secret, &init)?;
        let secret = secret.set_path(&[C::id(), Id::hash(&location)])?;
        let key = Key::Secret(location.key);
        let mut channel = Channel::new(channel::Location{server: Name::orange_me(), discovery: key, encryption: key});
        let c = C::init(init.clone(), Metadata::pending(secret.name()));
        channel.queue_mut().push_back(Signed::new(&secret, Message::Init(init)));
        Ok(Instance{
            secret,
            location,
            channel,
            confirmed: None,
            pending: Some(c),
        })
    }

    pub fn receive(secret: Secret, location: Location) -> Result<Self, Error> {
        let key = Key::Secret(location.key);
        let channel = Channel::new(channel::Location{server: location.server, discovery: key, encryption: key});
        let secret = secret.set_path(&[C::id(), Id::hash(&location)])?;
        Ok(Instance{
            secret,
            channel,
            location,
            confirmed: None,
            pending: None,
        })
    }

    pub fn location(&self) -> &Location {&self.location}
    pub fn id(&self) -> Id {Id::hash(&self.location)}
    pub fn confirmed(&self) -> Option<&C> {self.confirmed.as_ref()}
    pub fn pending(&self) -> &C {self.pending.as_ref().unwrap()}

    pub fn send(&mut self, message: C::Message) -> C::Result {
        self.channel.queue_mut().push_back(Signed::new(&self.secret, Message::Message(message.clone())));
        self.pending.as_mut().unwrap().apply(message, Metadata::pending(self.secret.name()))
    }

    pub fn start(&mut self) -> Request {self.channel.start()}
    pub fn request(&mut self) -> Option<Request> {self.channel.request()}

    pub async fn response<R: Resolver>(&mut self, resolver: &mut R, response: Response) -> Output<C::Result> {
        match self.channel.response(response) {
            channel::Output::Subscribed => Output::Subscribed,
            channel::Output::Created(time, signed) => self.process(time, signed.signer, signed.payload, true),
            channel::Output::Read(time, signed) => match self.verify(resolver, time, signed).await {
                Some((name, msg)) => self.process(time, name, msg, false),
                None => Output::Garbage
            },
            channel::Output::Garbage => Output::Garbage
        }
    }

    async fn verify<R: Resolver>(&mut self, resolver: &mut R, time: u64, message: Signed<Message<C>>) -> Option<(Name, Message<C>)> {
        println!("resolving");
        let identity = resolver.resolve(message.signer, Some(time)).await;
        println!("resolved");
        message.verify(&identity, &[C::id(), Id::hash(&self.location)]).ok()?;
        Some((message.signer, message.payload))
    }

    fn process(&mut self, time: u64, name: Name, message: Message<C>, created: bool) -> Output<C::Result> {
        let result = match (&mut self.confirmed, message) {
            (Some(confirmed), Message::Message(msg)) => {
                Some(confirmed.apply(msg, Metadata::confirmed(name, time)))
            },
            (none, Message::Init(init)) if none.is_none() && Id::hash(&(&init, name)) == self.location.instance => {
                *none = Some(C::init(init, Metadata::confirmed(name, time)));
                None
            },
            (_, Message::Init(_)) => {return Output::Garbage;}
            (None, Message::Message(_)) => {return Output::Garbage;}
        };
        self.pending = self.confirmed.clone();
        let results = self.channel.queue().iter().filter_map(|msg| match &msg.payload {
            Message::Message(msg) => Some(C::apply(self.pending.as_mut().unwrap(), msg.clone(), Metadata::pending(self.secret.name()))),
            Message::Init(_) => None
        }).collect();
        match result {
            Some(result) if created => Output::Created(result, results),
            Some(result) => Output::Read(result, results),
            None => Output::Init(results),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::names::DefaultResolver;
    use crate::client::Client;

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

        let mut a_room = Instance::new(alice.clone(), "MyRoom".to_string()).unwrap();
        let mut resolver = DefaultResolver::start();
        let client = Client::new(DefaultResolver::start()).await;

        let mut make_request = async |room: &mut Instance<Room>| {
            let response = client.send(room.request().unwrap()).await.recv().await.unwrap();
            room.response(&mut resolver, response).await
        };

        assert_eq!(a_room.pending(), &Room{author: alice.name(), name: "MyRoom".to_string(), messages: vec![]});
        assert_eq!(a_room.confirmed(), None);

        assert_eq!(make_request(&mut a_room).await, Output::Init(vec![]));

        assert_eq!(a_room.confirmed(), Some(&Room{author: alice.name(), name: "MyRoom".to_string(), messages: vec![]}));

        assert_eq!(a_room.send("Hello Bob".to_string()), 1);

        assert_eq!(a_room.pending(), &Room{author: alice.name(), name: "MyRoom".to_string(), messages: vec![
            Message{author: alice.name(), body: "Hello Bob".to_string(), sent: false}
        ]});

        assert_eq!(make_request(&mut a_room).await, Output::Created(1, vec![]));

        assert_eq!(a_room.confirmed(), Some(&Room{author: alice.name(), name: "MyRoom".to_string(), messages: vec![
            Message{author: alice.name(), body: "Hello Bob".to_string(), sent: true}
        ]}));

        let mut b_room = Instance::receive(bob.clone(), *a_room.location()).unwrap();
        assert_eq!(b_room.confirmed(), None);

        assert_eq!(make_request(&mut b_room).await, Output::Init(vec![]));
        assert_eq!(b_room.pending(), &Room{author: alice.name(), name: "MyRoom".to_string(), messages: vec![]});
        assert_eq!(b_room.confirmed(), Some(&Room{author: alice.name(), name: "MyRoom".to_string(), messages: vec![]}));
        
        assert_eq!(b_room.send("Hi Alice".to_string()), 1);
        assert_eq!(b_room.pending(), &Room{author: alice.name(), name: "MyRoom".to_string(), messages: vec![
            Message{author: bob.name(), body: "Hi Alice".to_string(), sent: false}
        ]});

        assert_eq!(make_request(&mut b_room).await, Output::Read(1, vec![2]));
        assert_eq!(b_room.confirmed(), Some(&Room{author: alice.name(), name: "MyRoom".to_string(), messages: vec![
            Message{author: alice.name(), body: "Hello Bob".to_string(), sent: true}
        ]}));

        assert_eq!(b_room.pending(), &Room{author: alice.name(), name: "MyRoom".to_string(), messages: vec![
            Message{author: alice.name(), body: "Hello Bob".to_string(), sent: true},
            Message{author: bob.name(), body: "Hi Alice".to_string(), sent: false}
        ]});
    }
}
