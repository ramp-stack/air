mod cache;
mod ams;
pub use ams::Ref;

pub mod names;
pub use names::{Secret, Name, Id};
use names::Resolver;

mod storage;

mod server;
use server::Purser;

mod channel;

mod contract;
pub use contract::{Contract, Reactant, Reactants, Instance, DynInstance, Context, Update, Listner};

use std::any::TypeId;
use tokio::sync::watch::{channel, Receiver, Sender};
use std::collections::BTreeMap;
use std::pin::Pin;

pub trait Service: Send + 'static {
    fn run(&mut self, ctx: &mut Context) -> impl Future<Output = Option<std::time::Duration>> + Send;
}

type ErasedService = Box<dyn FnOnce(Receiver<Option<bool>>, Context) -> Pin<Box<dyn Future<Output = ()> + Send>>>;
#[derive(Default)]
pub struct Services(BTreeMap<TypeId, ErasedService>);
impl Services {
    #[allow(clippy::should_implement_trait)]
    pub fn add<S: Service>(mut self, mut service: S) -> Self {
        self.0.insert(TypeId::of::<S>(), Box::new(move |mut watcher: Receiver<Option<bool>>, mut ctx: Context| {
            Box::pin(async move { loop {
                while !watcher.borrow_and_update().unwrap_or_default() {
                    if watcher.changed().await.is_ok() {return;}
                    if watcher.borrow_and_update().is_none() {return;}
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

#[derive(Clone, Debug)]
pub struct Air{
    handle: tokio::runtime::Handle,
    remote: Sender<Option<bool>>,
    watcher: Receiver<Option<bool>>,
    secret: Secret,
    name: Name,
    purser: Purser,
    resolver: Resolver
}
impl Air {
    pub fn me(&self) -> Name {self.name}

    fn new(secret: Secret) -> Self {
        let runtime = tokio::runtime::Builder::new_multi_thread().enable_time().enable_io().build().unwrap();
        let _guard = runtime.enter();
        let resolver = names::Resolver::start();
        let purser = server::Purser::start(resolver.clone());

        let (remote, mut watcher) = channel(Some(true));
        let air = Air{
            handle: runtime.handle().clone(),
            remote,
            watcher: watcher.clone(),
            name: secret.name(),
            secret,
            purser,
            resolver
        };
        std::thread::spawn(move || runtime.block_on(async move { loop {
            if watcher.changed().await.is_ok()
            && watcher.borrow_and_update().is_none() {
                return;
            }
        }}));
        air 
    }

    pub fn start(secret: Secret) -> (Self, Context) {
        let air = Self::new(secret);
        let context = air.handle.clone().block_on(async {contract::Manager::start(air.clone())});
        (air, context)
    }

    pub fn start_server(secret: Secret) {
        let air = Self::new(secret.clone());
        air.handle.block_on(server::Chandler::start(secret))
    }

    pub fn start_services(&self, services: Services, context: &mut Context) {
        for (_, service) in services.0 {
            self.handle.spawn(service(self.watcher.clone(), context.clone()));
        }
    }

    pub fn pause(&self) {self.remote.send(Some(false)).unwrap();}
    pub fn resume(&self) {self.remote.send(Some(true)).unwrap();}
    pub fn shutdown(self) {self.remote.send(None).unwrap();}
}

#[cfg(test)]
mod test {
    use crate::{Air, Contract, Reactant, Reactants, Instance, Name, Secret, Id, Context, Service, Services, Listner};
    use serde::{Serialize, Deserialize};
    use std::collections::BTreeMap;
    use std::time::Duration;

    #[derive(Default)]
    pub struct ChatBot(Listner<Room>);
    impl Service for ChatBot {
        async fn run(&mut self, ctx: &mut Context) -> Option<Duration> {
            if let (room, Some(update)) = self.0.listen(ctx).await
            && let Some(Ok(id)) = update.as_reactant::<_, SendMessage>() {
                let message = room.confirmed().unwrap().messages.values().find(|m| m.id == id).unwrap().clone();
                if !message.body.contains("ChatBot Quoting") {
                    room.apply(SendMessage(Id::random(), format!("ChatBot Quoting {} Saying: \"{}\"", message.author, message.body))).unwrap();
                }
            }
            Some(Duration::from_secs(0))
        }
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

    #[derive(Clone, Debug, PartialEq)]
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

    #[derive(Clone, Debug, PartialEq)]
    pub struct InvalidAuthor(Name);
    impl std::error::Error for InvalidAuthor {}
    impl std::fmt::Display for InvalidAuthor {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {write!(f, "Message can only be edited by {}", self.0)}
    }

    #[derive(Serialize, Deserialize, Clone, Debug)]
    pub struct EditMessage(Id, String);
    impl Reactant<Room> for EditMessage {
        type Result = Result<bool, InvalidAuthor>;

        fn id() -> Id {Id::hash("EditMessage")}

        fn apply(self, room: &mut Room, signer: Name, _timestamp: u64) -> Self::Result {
            if let Some(message) = room.messages.values_mut().find(|m| m.id == self.0) {
                if message.author != signer {Err(InvalidAuthor(message.author))?}
                message.body = self.1;
                Ok(true)
            } else {Ok(false)}
        }
    }


    #[test]
    fn test() {
        let (alice, mut a_ctx) = Air::start(Secret::new());
        let (bob, mut b_ctx) = Air::start(Secret::new());
        alice.start_services(Services::default().add(ChatBot::default()), &mut a_ctx);

        let mut room: Instance<Room> = a_ctx.create::<Room>("MyRoom".to_string());
        let mut other_instance = room.clone();
        let id = room.apply(SendMessage(Id::random(), "Hi Bob".to_string())).unwrap();
        assert!(other_instance.pending_updated());
        assert!(!other_instance.pending_updated());
        assert_eq!(other_instance.apply(EditMessage(id, "GoodBye Bob".to_string())), Ok(true));
        assert!(room.pending_updated());

        std::thread::sleep(Duration::from_millis(100));
        a_ctx.list::<Room>().into_iter().for_each(|i| {
            assert_eq!(i.confirmed().unwrap().as_ref(), i.pending().as_ref());
        });

        let room = a_ctx.list::<Room>().pop().unwrap();
        room.share(bob.me());
        b_ctx.register::<Room>();

        std::thread::sleep(Duration::from_millis(100));
        let mut room = b_ctx.list::<Room>().pop().unwrap();
        //try_apply will not publish the reactant unless the try operation succeeds(until try trait is stabalized only works for Result)
        assert_eq!(room.try_apply(EditMessage(id, "Bob Edititing Alices Message".to_string())), Err(InvalidAuthor(alice.me())));

        room.clear_confirmed();
        let id = room.apply(SendMessage(Id::random(), "Hi Alice".to_string())).unwrap();
        assert_eq!(room.apply(SendMessage(id, "Sent With Existing Message Id".to_string())), Err(MessageExists(id)));

        std::thread::sleep(Duration::from_millis(200));
        let update = room.confirmed_update().unwrap();
        assert_eq!(update.as_reactant::<Room, SendMessage>().unwrap(), Ok(id))
    }
}
