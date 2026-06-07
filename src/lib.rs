mod cache;
mod ams;
pub use ams::Ref;

pub mod names;
pub use names::{Secret, Name, Id};

mod storage;

mod server;

mod runtime;

#[derive(Clone, Debug)]
struct Handle{
    pub handle: runtime::Handle,
    pub secret: Secret,
    pub name: Name,
    pub purser: server::Purser,
    pub resolver: names::Resolver
}
impl Handle {
    pub fn new(handle: runtime::Handle, secret: Secret) -> Self {
        let _guard = handle.handle.enter();
        let resolver = names::Resolver::start();
        let purser = server::Purser::start(resolver.clone());
        Handle{handle, resolver, purser, name: secret.name(), secret}
    }
}

mod channel;

mod contract;
pub use contract::{Contract, Reactant, Reactants, Instance, DynInstance, Context, Update};

pub trait Service: Send + 'static {
    fn run(&mut self, ctx: &mut Context) -> impl Future<Output = Option<std::time::Duration>> + Send;
}
use std::any::TypeId;
use std::collections::BTreeMap;
use std::pin::Pin;

type ErasedService = Box<dyn FnOnce(runtime::Handle, Context) -> Pin<Box<dyn Future<Output = ()> + Send>>>;
#[derive(Default)]
pub struct Services(BTreeMap<TypeId, ErasedService>);
impl Services {
    #[allow(clippy::should_implement_trait)]
    pub fn add<S: Service>(mut self, mut service: S) -> Self {
        self.0.insert(TypeId::of::<S>(), Box::new(move |mut handle: runtime::Handle, mut ctx: Context| {
            Box::pin(async move { loop {
                while !handle.watcher.borrow_and_update().unwrap_or_default() {
                    if handle.watcher.changed().await.is_ok() {return;}
                    if handle.watcher.borrow_and_update().is_none() {return;}
                    continue;
                }

                match service.run(&mut ctx).await {
                    Some(duration) => tokio::time::sleep(duration).await,
                    None => {return;}
                }
            }})
        }));
        self
    }
}

use tokio::sync::watch;

pub struct Air(runtime::Handle, watch::Sender<Option<bool>>, Context);
impl Air {
    pub fn start(secret: Secret) -> (Context, Self) {
        let (handle, remote) = runtime::Handle::new();
        let context = handle.clone().block_on(async {contract::Manager::start(Handle::new(handle.clone(), secret))});
        (context.clone(), Air(handle, remote, context))
    }

    pub fn start_server(secret: Secret) {
        let (handle, _remote) = runtime::Handle::new();
        handle.block_on(server::Chandler::start(secret))
    }

    pub fn start_services(&self, services: Services) {
        for (_, service) in services.0 {
            self.0.spawn(service(self.0.clone(), self.2.clone()));
        }
    }

    pub fn pause(&self) {self.1.send(Some(false)).unwrap();}
    pub fn resume(&self) {self.1.send(Some(true)).unwrap();}
    pub fn shutdown(self) {self.1.send(None).unwrap();}
}

#[cfg(test)]
mod test {
    use crate::{Air, Contract, Reactant, Reactants, Instance, Name, Secret, Id, Context, Service};
    use serde::{Serialize, Deserialize};
    use std::collections::BTreeMap;
    use std::time::Duration;

    #[derive(Default)]
    pub struct ChatBot(u32, BTreeMap<Id, Instance<Room>>);
    impl Service for ChatBot {
        async fn run(&mut self, ctx: &mut Context) -> Option<Duration> {
          //match ctx.listen::<Room>() {
          //    Update::Instance(room) => self.1
          //}
          //ctx.list(&ChatRoom::id()).into_iter().for_each(|id| {
          //    ctx.send(id, "/messages", SendMessage("This is an automated message: 'Keep It Quiet!'".to_string())).unwrap();
          //});
            Some(Duration::from_secs(5))
        }
    }

    #[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
    pub struct Dummy(String);
    impl Contract for Dummy {
        type Init = String;

        fn id() -> Id {Id::hash("Dummy")}

        fn init(init: Self::Init, signer: Name, _timestamp: u64) -> Self {
            Dummy(init)
        }

        fn reactants() -> Reactants<Dummy> {Reactants::default()}
    }

    #[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
    pub struct Message {
        author: Name,
        timestamp: u64,
        body: String,
        id: Id
    }

    #[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
    pub struct Room {
        author: Name,
        name: String,
        messages: BTreeMap<u64, Message>
    }
    impl Contract for Room {
        type Init = String;

        fn id() -> Id {Id::hash("Room")}

        fn init(init: Self::Init, signer: Name, _timestamp: u64) -> Self {
            Room {
                author: signer,
                name: init, 
                messages: BTreeMap::new()
            }
        }

        fn reactants() -> Reactants<Room> {
            Reactants::default().add::<SendMessage>().add::<EditMessage>()
        }
    }

    #[derive(Clone, Debug)]
    pub struct MessageExists(Id);
    impl std::error::Error for MessageExists {}
    impl std::fmt::Display for MessageExists {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {write!(f, "{:?}", self)}
    }

    #[derive(Serialize, Deserialize, Clone, Debug)]
    pub struct SendMessage(Id, String);
    impl Reactant<Room> for SendMessage {
        type Result = Result<Id, MessageExists>;

        fn id() -> Id {Id::hash("SendMessage")}

        fn apply(self, room: &mut Room, signer: Name, timestamp: u64) -> Self::Result {
            if room.messages.values().any(|m| m.id == self.0) {Err(MessageExists(self.0))?}
            room.messages.entry(timestamp).or_insert(Message{author: signer, timestamp, body: self.1, id: self.0});
            Ok(self.0)
        }
    }

    #[derive(Serialize, Deserialize, Clone, Debug)]
    pub struct EditMessage(Id, String);
    impl Reactant<Room> for EditMessage {
        type Result = bool;

        fn id() -> Id {Id::hash("EditMessage")}

        fn apply(self, room: &mut Room, _signer: Name, _timestamp: u64) -> Self::Result {
            room.messages.values_mut().find(|m| m.id == self.0).map(|m| {m.body = self.1; true}).unwrap_or_default()
        }
    }


    #[test]
    fn test() {
        let (mut air, _) = Air::start(Secret::new());

        let mut room: Instance<Room> = air.create::<Room>("MyRoom".to_string());
        let mut other_instance = room.clone();
        let id = room.apply(SendMessage(Id::random(), "Hi Bob".to_string())).unwrap();
        assert!(other_instance.pending_has_update());
        assert!(!other_instance.pending_has_update());
        assert!(other_instance.apply(EditMessage(id, "GoodBye Bob".to_string())));
        assert!(room.pending_has_update());

        std::thread::sleep(Duration::from_millis(100));
        air.list::<Room>().into_iter().for_each(|mut i| {
            let c: Room = i.confirmed().unwrap().as_ref().clone();
            assert_eq!(c, i.pending().as_ref().clone())
        });

        let dummy = air.create::<Dummy>("MyRoom".to_string());

        let mut room = air.list::<Room>().pop().unwrap();
        let id = room.apply(SendMessage(Id::random(), "Hi Alice".to_string())).unwrap();
        loop {}

      //let update = room.get_confirmed_update().unwrap();
      //assert_eq!(id, update.as_reactant::<Room, SendMessage>().unwrap().unwrap())
    }
}
