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
pub use contract::{Contract, Reactant, Reactants, Instance, AnyInstance, AnyOutput, Metadata, Pending, PendingResult, Instances};

mod service;
pub use service::{Service, Services, Lock};

use tokio_util::task::TaskTracker;
use tokio_util::sync::CancellationToken;

#[derive(Clone)]
pub struct Context(Instances, Air);
impl Context {
    pub fn me(&self) -> Name {self.1.name}
    pub fn service_secret<S: Service>(&self) -> Secret {self.1.service_secret::<S>()}
    pub fn register<C: Contract>(&self) {self.0.register::<C>()}
    pub fn create<C: Contract>(&self, init: C::Init) -> Instance<C> {self.0.create(init)}
    pub fn list<C: Contract>(&self) -> Vec<Instance<C>> {self.0.list::<C>()}
    pub fn instances(&self) -> Instances {self.0.clone()}
}
    
#[derive(Clone, Debug)]
pub struct Air{
    handle: tokio::runtime::Handle,
    token: CancellationToken,
    tasks: TaskTracker,
    secret: Secret,
    name: Name,
    purser: Purser,
    resolver: Resolver
}
impl Air {
    pub fn me(&self) -> Name {self.name}

    pub fn service_secret<S: Service>(&self) -> Secret {self.secret.derive(&[S::id()])}

    fn new(secret: Secret) -> Self {
        let runtime = tokio::runtime::Builder::new_multi_thread().enable_time().enable_io().build().unwrap();
        let _guard = runtime.enter();
        let resolver = names::Resolver::start();
        let purser = server::Purser::start(resolver.clone());

        let token = CancellationToken::new();
        let tasks = TaskTracker::new();
        let air = Air{
            handle: runtime.handle().clone(),
            token: token.clone(),
            tasks: tasks.clone(),
            name: secret.name(),
            secret,
            purser,
            resolver
        };
        std::thread::spawn(move || runtime.block_on(async move {
            token.cancelled().await;
            tasks.wait().await;
        }));
        air 
    }

    pub fn spawn<F: Future<Output = ()> + Send + 'static>(&self, future: F) {
        self.tasks.spawn_on(future, &self.handle);
    }

    pub fn start(secret: Secret, services: Services) -> (Self, Context) {
        let air = Self::new(secret.clone());
        let instances = air.handle.clone().block_on(async {contract::Manager::start(air.clone())});
        let context = Context(instances, air.clone());
        services.start(context.clone());
        (air, context)
    }

    pub fn start_server(secret: Secret) {
        let air = Self::new(secret.clone());
        air.handle.block_on(server::Chandler::start(secret))
    }

    pub fn shutdown(self) {
        self.token.cancel();
        self.tasks.close();
        self.handle.clone().block_on(self.tasks.wait());
    }
}

#[cfg(test)]
mod test {
    use crate::{Air, Contract, Reactant, Reactants, Instance, Name, Secret, Id, Context, Service, Services, Listner, Metadata};
    use serde::{Serialize, Deserialize};
    use std::collections::BTreeMap;
    use std::time::Duration;

    #[derive(Default)]
    pub struct ChatBot(Listner<Room>);
    impl Service for ChatBot {
        fn id() -> Id {Id::hash("CHATBOT")}
        async fn new(_ctx: &mut Context, _secret: Secret) -> Self {ChatBot(Listner::default())}
        async fn run(&mut self, ctx: &mut Context) {
            if let (room, Some(Ok(id))) = self.0.listen::<SendMessage>(ctx).await {
                let message = room.confirmed().unwrap().messages.values().find(|m| m.id == id).unwrap().clone();
                if message.author == ctx.me() && !message.body.contains("ChatBot Replying") {
                    room.apply(SendMessage(Id::random(), format!("ChatBot Replying to \"{:.10}...\": I totally agree", message.body))).load().clone().unwrap();
                }
            }
        }
        async fn shutdown(self, ctx: &mut Context) {
            for mut room in ctx.list::<Room>() {
                room.apply(SendMessage(Id::random(), "ChatBot Shutting Down".to_string())).load().clone().unwrap();
            }
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

        fn init(init: Self::Init, metadata: Metadata) -> Self {
            Room {
                author: metadata.signer,
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

        fn apply(self, room: &mut Room, metadata: Metadata) -> Self::Result {
            if room.messages.values().any(|m| m.id == self.0) {Err(MessageExists(self.0))?}
            room.messages.entry(metadata.timestamp).or_insert(Message{author: metadata.signer, timestamp: metadata.timestamp, body: self.1, id: self.0});
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

        fn apply(self, room: &mut Room, metadata: Metadata) -> Self::Result {
            if let Some(message) = room.messages.values_mut().find(|m| m.id == self.0) {
                if message.author != metadata.signer {Err(InvalidAuthor(message.author))?}
                message.body = self.1;
                Ok(true)
            } else {Ok(false)}
        }
    }


    #[test]
    fn test() {
        let (alice, mut a_ctx) = Air::start(Secret::new(), Services::default().add::<ChatBot>());
        let (bob, mut b_ctx) = Air::start(Secret::new(), Services::default());

        let mut room: Instance<Room> = a_ctx.create::<Room>("MyRoom".to_string());
        let mut other_instance = room.clone();
        let id = room.apply(SendMessage(Id::random(), "Hi Bob".to_string())).load().clone().unwrap();
        assert!(other_instance.pending_updated());
        assert!(!other_instance.pending_updated());
        assert_eq!(*other_instance.apply(EditMessage(id, "GoodBye Bob".to_string())).load(), Ok(true));
        assert!(room.pending_updated());

        std::thread::sleep(Duration::from_millis(100));
        a_ctx.list::<Room>().into_iter().for_each(|i| {
            assert_eq!(i.confirmed().unwrap().as_ref(), i.pending().as_ref());
        });

        let mut a_room = a_ctx.list::<Room>().pop().unwrap();
        a_room.share(bob.me());
        b_ctx.register::<Room>();

        std::thread::sleep(Duration::from_millis(100));
        let mut room = b_ctx.list::<Room>().pop().unwrap();
        //try_apply will not publish the reactant unless the try operation succeeds(until try trait is stabalized only works for Result)
        assert_eq!(room.try_apply(EditMessage(id, "Bob Edititing Alices Message".to_string())), Err(InvalidAuthor(alice.me())));

        room.clear_confirmed();
        println!("1Before");
        std::thread::sleep(Duration::from_millis(200));
        println!("1After");

        let id = room.apply(SendMessage(Id::random(), "Hi Alice".to_string())).load().clone().unwrap();
        //assert_eq!(*room.apply(SendMessage(id, "Sent With Existing Message Id".to_string())).load(), Err(MessageExists(id)));
        println!("Before");
        std::thread::sleep(Duration::from_millis(200));
        println!("After");
        let update = a_room.confirmed_update::<SendMessage>().unwrap();
        assert_eq!(update, Ok(id))
    }
}
