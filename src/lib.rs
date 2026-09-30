pub mod names;
pub use names::{Secret, Name, Id};

pub mod storage;

pub mod channel;

pub mod contract;

pub mod inbox;

pub mod websocket;
pub mod server;
pub mod client;





//Services need to process a channel and return results in the same or other channel,
//Services often run per one per user across all devices

//Every device needs to run all the instances they need, a Checkpoint service can exist to speed up
//recovering instances, But all real time information is processed by all online devices.

//In the future maverick will provide processes that run once per device
//As well as the Services that run once per user across all maverick apps/devices


//  //Holds all running instances
//  static RUNNING

//  //Holds all instances regardless of them running
//  static DISCOVERED

//  //Sharing
//  //
//  //Storage/Discovery
//  //
//  //


//  /// Arguable all this file should be in maverick,
//  // Except for the fact most of the code that will be here is managing the higharchy between
//  // inbox/storage and running instances
//  //
//  // A manager Would have to opperate in a top down manner letting maverick "run" the child instances



//  #[derive(Debug, Clone)]
//  pub struct Instance<C: Contract>(Arc<ArcSwap<contract::Instance<C>>>, Arc<Tx<mpsc::List<(C::Message, AsyncRx<spsc::One<C::Result>>)>>>);
//  impl<C: Contract> Instance<C> {
//      pub fn new<R: Resolver>(resolver: R, purser: Purser, secret: Secret, id: Id) -> Self {
//          //TODO: check if its already RUNNING
//          //TODO: attempt recovery from the database
//          //TODO: attempt recovery the checkpoint
//          let location = Location{server: Name::orange_me(), discovery: secret.harden().derive(&[id]).public_key()};
//          let instance = contract::Instance::<C>::new(secret, location);
//          let instance = Arc::new(ArcSwap::new(Arc::new(instance)));
//          let (tx, rx) = mpsc::build(mpsc::List::new());

//          tokio::spawn(Self::run(resolver, purser, instance.clone(), rx))

//          Instance(instance, Arc::new(tx))
//      }

//      async fn run<R: Resolver>(resolver: R, purser: Purser, instance: Arc<ArcSwap<contract::Instance<C>>>, rx: Rx<mpsc::List<(C::Message, AsyncRx<spsc::One<C::Result>>)>>) {
//          //1. start by making a request
//          //2. listen for response and new sends
//          //3. update instance and request after proccessing a send and respond with result
//          //      Only interupt the current request if its a read/subscrbe and I have a new send
//          //4. update the database
//      }

//      pub fn pending(&self) -> &C {self.0.pending()}
//      pub fn confirmed(&self) -> &C {self.0.confirmed()}

//      pub fn send(&self, message: C::Message) -> C::Result {
//          let (sp, sc) = spsc::build(spsc::One::new());
//          self.1.send((message, sp)).unwrap();
//          sc.recv().unwrap()
//      }

//      pub fn share(&self, name: Name) {
//      }
//  }











//  pub struct Cache(Connection);
//  impl Default for Cache {fn default() -> Self {Self::new()}}
//  impl Cache {
//      pub fn new() -> Self {
//          let connection = Connection::open("STORAGE.db").unwrap();

//          connection.execute("CREATE TABLE if not exists instances(
//              contract_id TEXT NOT NULL,
//              instance_id TEXT NOT NULL,
//              payload BLOB NOT NULL,
//          );", []).unwrap();

//          Cache(connection)
//      }

//      pub fn recover<C: Contract>(&mut self) -> HashMap<Id, Instance<C>> {

//      

//      }

//      pub fn cache<C: Contract>(&mut self, instance: &Instance<C>) {
//          self.0.execute(
//              "INSERT INTO instances(contract_id, instance_id, payload)
//               VALUES (?1, ?2, ?3) ON CONFLICT DO UPDATE SET payload=?3;",
//              params![
//                  C::id().to_string(),
//                  instance.id().to_string(),
//                  postcard::to_allocvec(&instance).unwrap(),
//              ],
//          ).unwrap();
//      }
//  }
























//  #[derive(Clone)]
//  ///When cloned contains a base state
//  pub struct Context(contract::Contracts, Air);
//  impl Context {
//      pub fn me(&self) -> Name {self.1.name}
//      pub fn service_secret<S: Service>(&self) -> Secret {self.1.service_secret::<S>()}

//      pub fn create<C: Contract>(&self) -> Id {}
//      pub fn list<C: Contract>(&self) -> HashMap<Id, Vec<Instance<C>>> {}


//      pub fn create<C: Contract>(&self, init: C::Init) -> Instance<C> {self.0.create(init)}
//      pub fn list<C: Contract>(&self) -> std::collections::HashMap<Id, Instance<C>> {self.0.list()}
//      pub fn instances<C: Contract>(&self) -> Instances<C> {Instances::new(self.0.clone())}
//  }

//  #[derive(Clone)]
//  pub struct Air{
//      handle: tokio::runtime::Handle,
//      token: CancellationToken,
//      tasks: TaskTracker,
//      secret: Secret,
//      name: Name,
//      purser: Purser,
//      resolver: Resolver,
//      store: Box<dyn Store>
//  }
//  impl Air {
//      pub fn me(&self) -> Name {self.name}

//      fn set<S: Serialize>(&self, key: &str, value: &S) {self.store.set(key, postcard::to_allocvec(&value).unwrap())}
//      fn get<D: for<'a> Deserialize<'a>>(&self, key: &str) -> Option<D> {self.store.get(key).and_then(|b| postcard::from_bytes(&b).ok())}
//    //pub fn service_secret<S: Service>(&self) -> Secret {self.secret.derive(&[S::id()])}

//    //pub fn start(store: impl Store, services: Services) -> (Self, Context) {
//    //    let air = Self::new(store);
//    //    let instances = air.handle.clone().block_on(async {contract::Manager::start(air.clone())});
//    //    let context = Context(instances, air.clone());
//    //    services.start(context.clone());
//    //    (air, context)
//    //}

//    //pub fn start_server(store: impl Store) {
//    //    let air = Self::new(store);
//    //    air.handle.block_on(server::Chandler::start(secret))
//    //}

//    //fn new(secret: Secret, cache: PathBuf) -> Self {
//    //    let runtime = tokio::runtime::Builder::new_multi_thread().enable_time().enable_io().build().unwrap();
//    //    let _guard = runtime.enter();
//    //    let resolver = names::Resolver::start();
//    //    let purser = server::Purser::start(resolver.clone());

//    //    let token = CancellationToken::new();
//    //    let tasks = TaskTracker::new();
//    //    let air = Air{
//    //        handle: runtime.handle().clone(),
//    //        token: token.clone(),
//    //        tasks: tasks.clone(),
//    //        name: secret.name(),
//    //        secret,
//    //        purser,
//    //        resolver,
//    //        store: Box::new(store)
//    //    };
//    //    std::thread::spawn(move || runtime.block_on(async move {
//    //        token.cancelled().await;
//    //        tasks.wait().await;
//    //    }));
//    //    air 
//    //}

//      pub fn spawn<F: Future<Output = ()> + Send + 'static>(&self, future: F) {
//          self.tasks.spawn_on(future, &self.handle);
//      }

//      pub fn shutdown(self) {
//          self.token.cancel();
//          self.tasks.close();
//          self.handle.clone().block_on(self.tasks.wait());
//      }
//  }































//  pub mod lock;

//pub mod inbox;

//  #[cfg(test)]
//  mod test {
//      use crate::contract::{Contract, Instance, Metadata, Message};
//      use crate::websocket::Socket;
//      use crate::channel::Channel;
//      use crate::names::{DefaultResolver, Secret, Name, Id};
//      use serde::{Serialize, Deserialize};


//      #[derive(Serialize, Deserialize, Debug, Clone, Hash, PartialEq)]
//      pub struct Room {
//          name: String,
//          author: Name,
//          messages: Vec<(u64, Name, String)>
//      }
//      impl Contract for Room {
//          type Init = String;
//          type Message = String;

//          fn id() -> Id {Id::hash(&"Room")}

//          fn init(init: Self::Init, metadata: Metadata) -> Self {
//              Room{name: init, author: metadata.signer, messages: Vec::new()}
//          }

//          fn apply(&mut self, message: Self::Message, metadata: Metadata) {
//              self.messages.push((metadata.timestamp, metadata.signer, message));
//          }
//      }

//      #[tokio::test]
//      async fn test_client() {
//          let alice = Secret::new();
//          
//          let mut a_room = Instance::<Room>::new(&alice, "MyRoom".to_string());

//          let mut resolver = DefaultResolver::start();
//          let Socket(mut write, mut read) = Socket::connect(&mut resolver, a_room.location().server).await;

//          let mut confirm_step = async |secret: &Secret, room: &mut Channel<Instance<Room>>| {
//              let (midstate, _, request) = room.request(&secret).unwrap();
//              write.write(None, postcard::to_allocvec(&request).unwrap()).await;
//              let (idx, response) = read.read().await;
//              println!("response: {:?} :: {}", idx, secret.name());
//              room.response(&mut resolver, midstate, postcard::from_bytes(&response).unwrap()).await
//          };

//          //Alice creates a pending message
//          a_room.apply(Message::Message("Hello".to_string()));
//          assert_eq!(a_room.pending(), &Room{
//              name: "MyRoom".to_string(),
//              author: alice.name(),
//              messages: vec![
//                  (a_room.pending().messages[0].0, alice.name(), "Hello".to_string()), 
//              ]
//          });

//          //Alice waits and gets confirmation on the rooms inital state
//          confirm_step(&alice, &mut a_room).await;//1
//          assert_eq!(a_room.confirmed(), Some(&Room{
//              name: "MyRoom".to_string(),
//              author: alice.name(),
//              messages: vec![]
//          }));

//          //Alice waits and gets confirmation on her first message
//          confirm_step(&alice, &mut a_room).await;//2
//          assert_eq!(a_room.confirmed(), Some(&Room{
//              name: "MyRoom".to_string(),
//              author: alice.name(),
//              messages: vec![
//                  (a_room.pending().messages[0].0, alice.name(), "Hello".to_string()), 
//              ]
//          }));
//          
//          //Alice tries to get a response but gets nothing
//          confirm_step(&alice, &mut a_room).await;//3
//          assert_eq!(a_room.confirmed(), Some(&Room{
//              name: "MyRoom".to_string(),
//              author: alice.name(),
//              messages: vec![
//                  (a_room.pending().messages[0].0, alice.name(), "Hello".to_string()), 
//              ]
//          }));

//          //Alice creates a second message after not getting a response but does not send it yet
//          a_room.apply(Message::Message("Anyone there?".to_string().into()));
//          assert_eq!(a_room.pending(), &Room{
//              name: "MyRoom".to_string(),
//              author: alice.name(),
//              messages: vec![
//                  (a_room.pending().messages[0].0, alice.name(), "Hello".to_string()), 
//                  (a_room.pending().messages[1].0, alice.name(), "Anyone there?".to_string()), 
//              ]
//          });

//          //Bob gets the room
//          let bob = Secret::new();
//          let mut b_room = Channel::<Instance<Room>>::new(bob.name(), a_room.location().clone());

//          //Bob waits for its initial confirmation
//          confirm_step(&bob, &mut b_room).await;//4
//          assert_eq!(b_room.confirmed(), Some(&Room{
//              name: "MyRoom".to_string(),
//              author: alice.name(),
//              messages: vec![]
//          }));

//          //Bob sees the first message
//          confirm_step(&bob, &mut b_room).await;//5
//          assert_eq!(b_room.confirmed(), Some(&Room{
//              name: "MyRoom".to_string(),
//              author: alice.name(),
//              messages: vec![
//                  (b_room.pending().messages[0].0, alice.name(), "Hello".to_string()), 
//              ]
//          }));

//          //Bob responds to alice and waits for confirmation
//          b_room.apply(Message::Message("Hi Alice".to_string()));
//          confirm_step(&bob, &mut b_room).await;//6
//          assert_eq!(b_room.confirmed(), Some(&Room{
//              name: "MyRoom".to_string(),
//              author: alice.name(),
//              messages: vec![
//                  (b_room.pending().messages[0].0, alice.name(), "Hello".to_string()), 
//                  (b_room.pending().messages[1].0, bob.name(), "Hi Alice".to_string()), 
//              ]
//          }));

//          //Alice then tries to confirmed her second message and sees bob has sent something
//          confirm_step(&alice, &mut a_room).await;//7
//          assert_eq!(a_room.confirmed(), Some(&Room{
//              name: "MyRoom".to_string(),
//              author: alice.name(),
//              messages: vec![
//                  (a_room.pending().messages[0].0, alice.name(), "Hello".to_string()), 
//                  (a_room.pending().messages[1].0, bob.name(), "Hi Alice".to_string()), 
//              ]
//          }));

//          //Alice's pending state now shows what the room will look like if she confirms her previous message next
//          assert_eq!(a_room.pending(), &Room{
//              name: "MyRoom".to_string(),
//              author: alice.name(),
//              messages: vec![
//                  (a_room.pending().messages[0].0, alice.name(), "Hello".to_string()), 
//                  (a_room.pending().messages[1].0, bob.name(), "Hi Alice".to_string()), 
//                  (a_room.pending().messages[2].0, alice.name(), "Anyone there?".to_string()), 
//              ]
//          });

//          //Alice sends the pending message and waits for confirmation
//          confirm_step(&alice, &mut a_room).await;//8
//          assert_eq!(a_room.confirmed(), Some(&Room{
//              name: "MyRoom".to_string(),
//              author: alice.name(),
//              messages: vec![
//                  (a_room.pending().messages[0].0, alice.name(), "Hello".to_string()), 
//                  (a_room.pending().messages[1].0, bob.name(), "Hi Alice".to_string()), 
//                  (a_room.pending().messages[2].0, alice.name(), "Anyone there?".to_string()), 
//              ]
//          }));

//          //Alice sends a follow up and waits for confirmation
//          a_room.apply(Message::Message("Sorry bob, forgot to send my previous message earlier.".to_string()));
//          confirm_step(&alice, &mut a_room).await;//9
//          assert_eq!(a_room.confirmed(), Some(&Room{
//              name: "MyRoom".to_string(),
//              author: alice.name(),
//              messages: vec![
//                  (a_room.pending().messages[0].0, alice.name(), "Hello".to_string()), 
//                  (a_room.pending().messages[1].0, bob.name(), "Hi Alice".to_string()), 
//                  (a_room.pending().messages[2].0, alice.name(), "Anyone there?".to_string()), 
//                  (a_room.pending().messages[3].0, alice.name(), "Sorry bob, forgot to send my previous message earlier.".to_string()), 
//              ]
//          }));

//          confirm_step(&bob, &mut b_room).await;//10
//          confirm_step(&bob, &mut b_room).await;//11
//          assert_eq!(b_room.confirmed(), Some(&Room{
//              name: "MyRoom".to_string(),
//              author: alice.name(),
//              messages: vec![
//                  (b_room.pending().messages[0].0, alice.name(), "Hello".to_string()), 
//                  (b_room.pending().messages[1].0, bob.name(), "Hi Alice".to_string()), 
//                  (b_room.pending().messages[2].0, alice.name(), "Anyone there?".to_string()), 
//                  (b_room.pending().messages[3].0, alice.name(), "Sorry bob, forgot to send my previous message earlier.".to_string()), 
//              ]
//          }));
//      }
//  }















//  mod server;
//  use server::Purser;

//  mod channel;

//  mod contract;
//  pub use contract::{Contract, Reactant, Reactants, Instance, AnyInstance, AnyOutput, Metadata, Pending, PendingResult, Instances, Update};

//  mod service;
//  pub use service::{Service, Services, Lock};


//  #[derive(Clone)]
//  ///When cloned contains a base state
//  pub struct Context(contract::Contracts, Air);
//  impl Context {
//      pub fn me(&self) -> Name {self.1.name}
//      pub fn service_secret<S: Service>(&self) -> Secret {self.1.service_secret::<S>()}

//      pub fn create<C: Contract>(&self, init: C::Init) -> Id {}
//      pub fn list<C: Contract>(&self) -> HashMap<Id, Vec<Instance<C>>> {}


//      pub fn create<C: Contract>(&self, init: C::Init) -> Instance<C> {self.0.create(init)}
//      pub fn list<C: Contract>(&self) -> std::collections::HashMap<Id, Instance<C>> {self.0.list()}
//      pub fn instances<C: Contract>(&self) -> Instances<C> {Instances::new(self.0.clone())}
//  }
    
//  #[derive(Clone)]
//  pub struct Air{
//      handle: tokio::runtime::Handle,
//      token: CancellationToken,
//      tasks: TaskTracker,
//      secret: Secret,
//      name: Name,
//      purser: Purser,
//      resolver: Resolver,
//      store: Box<dyn Store>
//  }
//  impl Air {
//      pub fn me(&self) -> Name {self.name}

//      fn set<S: Serialize>(&self, key: &str, value: &S) {self.store.set(key, postcard::to_allocvec(&value).unwrap())}
//      fn get<D: for<'a> Deserialize<'a>>(&self, key: &str) -> Option<D> {self.store.get(key).and_then(|b| postcard::from_bytes(&b).ok())}
//    //pub fn service_secret<S: Service>(&self) -> Secret {self.secret.derive(&[S::id()])}

//    //pub fn start(store: impl Store, services: Services) -> (Self, Context) {
//    //    let air = Self::new(store);
//    //    let instances = air.handle.clone().block_on(async {contract::Manager::start(air.clone())});
//    //    let context = Context(instances, air.clone());
//    //    services.start(context.clone());
//    //    (air, context)
//    //}

//    //pub fn start_server(store: impl Store) {
//    //    let air = Self::new(store);
//    //    air.handle.block_on(server::Chandler::start(secret))
//    //}

//    //fn new(secret: Secret, cache: PathBuf) -> Self {
//    //    let runtime = tokio::runtime::Builder::new_multi_thread().enable_time().enable_io().build().unwrap();
//    //    let _guard = runtime.enter();
//    //    let resolver = names::Resolver::start();
//    //    let purser = server::Purser::start(resolver.clone());

//    //    let token = CancellationToken::new();
//    //    let tasks = TaskTracker::new();
//    //    let air = Air{
//    //        handle: runtime.handle().clone(),
//    //        token: token.clone(),
//    //        tasks: tasks.clone(),
//    //        name: secret.name(),
//    //        secret,
//    //        purser,
//    //        resolver,
//    //        store: Box::new(store)
//    //    };
//    //    std::thread::spawn(move || runtime.block_on(async move {
//    //        token.cancelled().await;
//    //        tasks.wait().await;
//    //    }));
//    //    air 
//    //}

//      pub fn spawn<F: Future<Output = ()> + Send + 'static>(&self, future: F) {
//          self.tasks.spawn_on(future, &self.handle);
//      }

//      pub fn shutdown(self) {
//          self.token.cancel();
//          self.tasks.close();
//          self.handle.clone().block_on(self.tasks.wait());
//      }
//  }

//  //  #[cfg(test)]
//  //  mod test {
//  //      use crate::{Air, Contract, Reactant, Reactants, Instance, Name, Secret, Id, Context, Service, Services, Listner, Metadata};
//  //      use serde::{Serialize, Deserialize};
//  //      use std::collections::BTreeMap;
//  //      use std::time::Duration;

//  //      #[derive(Default)]
//  //      pub struct ChatBot(Listner<Room>);
//  //      impl Service for ChatBot {
//  //          fn id() -> Id {Id::hash("CHATBOT")}
//  //          async fn new(_ctx: &mut Context, _secret: Secret) -> Self {ChatBot(Listner::default())}
//  //          async fn run(&mut self, ctx: &mut Context) {
//  //              if let (a_room, Some(Ok(id))) = self.0.listen::<SendMessage>(ctx).await {
//  //                  let message = a_room.confirmed().unwrap().messages.values().find(|m| m.id == id).unwrap().clone();
//  //                  if message.author == ctx.me() && !message.body.contains("ChatBot Replying") {
//  //                      a_room.apply(SendMessage(Id::random(), format!("ChatBot Replying to \"{:.10}...\": I totally agree", message.body))).load().clone().unwrap();
//  //                  }
//  //              }
//  //          }
//  //          async fn shutdown(self, ctx: &mut Context) {
//  //              for mut a_room in ctx.list::<Room>() {
//  //                  a_room.apply(SendMessage(Id::random(), "ChatBot Shutting Down".to_string())).load().clone().unwrap();
//  //              }
//  //          }
//  //      }

//  //      #[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
//  //      pub struct Message {
//  //          author: Name,
//  //          timestamp: u64,
//  //          body: String,
//  //          id: Id
//  //      }

//  //      #[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
//  //      pub struct Room {
//  //          author: Name,
//  //          name: String,
//  //          messages: BTreeMap<u64, Message>
//  //      }
//  //      impl Contract for Room {
//  //          type Init = String;
//  //          fn id() -> Id {Id::hash("Room")}

//  //          fn init(init: Self::Init, metadata: Metadata) -> Self {
//  //              Room {
//  //                  author: metadata.signer,
//  //                  name: init, 
//  //                  messages: BTreeMap::new()
//  //              }
//  //          }

//  //          fn reactants() -> Reactants<Room> {
//  //              Reactants::default().add::<SendMessage>().add::<EditMessage>()
//  //          }
//  //      }

//  //      #[derive(Clone, Debug, PartialEq)]
//  //      pub struct MessageExists(Id);
//  //      impl std::error::Error for MessageExists {}
//  //      impl std::fmt::Display for MessageExists {
//  //          fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {write!(f, "{:?}", self)}
//  //      }

//  //      #[derive(Serialize, Deserialize, Clone, Debug)]
//  //      pub struct SendMessage(Id, String);
//  //      impl Reactant<Room> for SendMessage {
//  //          type Result = Result<Id, MessageExists>;

//  //          fn id() -> Id {Id::hash("SendMessage")}

//  //          fn apply(self, a_room: &mut Room, metadata: Metadata) -> Self::Result {
//  //              if a_room.messages.values().any(|m| m.id == self.0) {Err(MessageExists(self.0))?}
//  //              a_room.messages.entry(metadata.timestamp).or_insert(Message{author: metadata.signer, timestamp: metadata.timestamp, body: self.1, id: self.0});
//  //              Ok(self.0)
//  //          }
//  //      }

//  //      #[derive(Clone, Debug, PartialEq)]
//  //      pub struct InvalidAuthor(Name);
//  //      impl std::error::Error for InvalidAuthor {}
//  //      impl std::fmt::Display for InvalidAuthor {
//  //          fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {write!(f, "Message can only be edited by {}", self.0)}
//  //      }

//  //      #[derive(Serialize, Deserialize, Clone, Debug)]
//  //      pub struct EditMessage(Id, String);
//  //      impl Reactant<Room> for EditMessage {
//  //          type Result = Result<bool, InvalidAuthor>;

//  //          fn id() -> Id {Id::hash("EditMessage")}

//  //          fn apply(self, a_room: &mut Room, metadata: Metadata) -> Self::Result {
//  //              if let Some(message) = a_room.messages.values_mut().find(|m| m.id == self.0) {
//  //                  if message.author != metadata.signer {Err(InvalidAuthor(message.author))?}
//  //                  message.body = self.1;
//  //                  Ok(true)
//  //              } else {Ok(false)}
//  //          }
//  //      }


//  //      #[test]
//  //      fn test() {
//  //          let (alice, mut a_ctx) = Air::start(Secret::new(), Services::default().add::<ChatBot>());
//  //          let (bob, mut b_ctx) = Air::start(Secret::new(), Services::default());

//  //          let mut a_room: Instance<Room> = a_ctx.create::<Room>("MyRoom".to_string());
//  //          let mut other_instance = a_room.clone();
//  //          let id = a_room.apply(SendMessage(Id::random(), "Hi Bob".to_string())).load().clone().unwrap();
//  //          assert!(other_instance.pending_updated());
//  //          assert!(!other_instance.pending_updated());
//  //          assert_eq!(*other_instance.apply(EditMessage(id, "GoodBye Bob".to_string())).load(), Ok(true));
//  //          assert!(a_room.pending_updated());

//  //          std::thread::sleep(Duration::from_millis(100));
//  //          a_ctx.list::<Room>().into_iter().for_each(|i| {
//  //              assert_eq!(i.confirmed().unwrap().as_ref(), i.pending().as_ref());
//  //          });

//  //          let mut a_a_room = a_ctx.list::<Room>().pop().unwrap();
//  //          a_a_room.share(bob.me());
//  //          b_ctx.register::<Room>();

//  //          std::thread::sleep(Duration::from_millis(100));
//  //          let mut a_room = b_ctx.list::<Room>().pop().unwrap();
//  //          //try_apply will not publish the reactant unless the try operation succeeds(until try trait is stabalized only works for Result)
//  //          assert_eq!(a_room.try_apply(EditMessage(id, "Bob Edititing Alices Message".to_string())), Err(InvalidAuthor(alice.me())));

//  //          a_room.clear_confirmed();
//  //          println!("1Before");
//  //          std::thread::sleep(Duration::from_millis(200));
//  //          println!("1After");

//  //          let id = a_room.apply(SendMessage(Id::random(), "Hi Alice".to_string())).load().clone().unwrap();
//  //          //assert_eq!(*a_room.apply(SendMessage(id, "Sent With Existing Message Id".to_string())).load(), Err(MessageExists(id)));
//  //          println!("Before");
//  //          std::thread::sleep(Duration::from_millis(200));
//  //          println!("After");
//  //          let update = a_a_room.confirmed_update::<SendMessage>().unwrap();
//  //          assert_eq!(update, Ok(id))
//  //      }
//  //  }
