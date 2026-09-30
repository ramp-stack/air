use crate::names::{Signature, Name, Id, Resolver};
use crate::storage::{Request, Response};

use std::collections::{HashMap};

use crossfire::{MAsyncTx, AsyncTx, AsyncRx, spsc, mpsc};
use crate::websocket::{Socket, Stream, Sink};

#[derive(Clone)]
pub struct Client(MAsyncTx<mpsc::List<(Request, AsyncTx<spsc::List<Response>>)>>);
impl Client {
    pub async fn new<R: Resolver + Send + 'static>(mut resolver: R) -> Self {
        let socket = Socket::connect(&mut resolver, Name::orange_me()).await;

        let (mp, sc) = mpsc::build(mpsc::List::new());
        let (sp, rc) = spsc::build(spsc::List::new());
        tokio::spawn(async move { Self::write(socket.0, sc, sp).await});
        tokio::spawn(async move {Self::read(resolver, socket.1, rc).await});
        Client(mp)
    }

    pub async fn send(&mut self, request: Request) -> AsyncRx<spsc::List<Response>> {
        let (sp, sc) = spsc::build(spsc::List::new());
        self.0.send((request, sp)).await.unwrap();
        sc
    }

    async fn write(mut sink: Sink, rx: AsyncRx<mpsc::List<(Request, AsyncTx<spsc::List<Response>>)>>, tx: AsyncTx<mpsc::List<(Id, AsyncTx<spsc::List<Response>>)>>) {
        while let Ok((request, responder)) = rx.recv().await {
            let hash = Id::hash(&request);
            sink.write(None, postcard::to_allocvec(&request).unwrap()).await;
            tx.send((hash, responder)).await.unwrap();
        }

    }
    async fn read<R: Resolver + 'static>(mut resolver: R, mut stream: Stream, rx: AsyncRx<spsc::List<(Id, AsyncTx<spsc::List<Response>>)>>) {
        let mut index = 0;
        let mut responders: HashMap<u64, (Id, AsyncTx<spsc::List<Response>>)> = HashMap::new();
        loop {tokio::select!{
            (i, bytes) = stream.read() => {
                println!("Read {:?}", i);
                if let Some((hash, responder)) = responders.get_mut(&i) && let Ok((signature, response)) = postcard::from_bytes::<(Signature, Response)>(&bytes) {
                    println!("r_count: {:?}: {:?}", i, hash);
                    let identity = resolver.resolve(Name::orange_me(), None).await;
                    if signature.verify(&identity, &[], Id::hash(&(hash, Id::hash(&response)))).is_ok() {
                        let remove = !matches!(&response, Response::Read(_, None));
                        println!("responded");
                        responder.send(response).await.unwrap();
                        if remove { responders.remove(&i); }
                    }
                }
            },
            Ok(responder) = rx.recv() => {
                println!("Awaiting {:?}", index);
                responders.insert(index, responder);
                index += 1;
            },
            else => break,
        };}
    }
}

//      pub struct Client(Secret, Context);
//      impl Client {
//          pub fn new(secret: Secret) -> Result<Self, Error> {
//              Ok(Client(secret, , Contracts::new(name)))
//          }

//          pub fn context(&self) -> &Context {&self.1}

//          pub fn run(self) {

//          }

//          pub fn register() {
//              
//          }

//          pub fn create() {
//              
//          }
//      }

//      #[derive(Debug, Clone)]
//      pub struct Instance<C: Contract>(Arc<ArcSwap<contract::Instance<C>>>, Arc<Tx<mpsc::List<(C::Message, AsyncRx<spsc::One<C::Result>>)>>>);
//      impl<C: Contract> Instance<C> {
//          //Assumes it is not already running
//          pub fn new<R: Resolver>(resolver: R, purser: Purser, secret: Secret, id: Id) -> Self {
//              //TODO: attempt recovery from the database
//              let location = Location{server: Name::orange_me(), discovery: secret.harden().derive(&[id]).public_key()};
//              let instance = contract::Instance::<C>::new(secret, location);
//              let instance = Arc::new(ArcSwap::new(Arc::new(instance)));
//              let (tx, rx) = mpsc::build(mpsc::List::new());

//              tokio::spawn(Self::run(resolver, purser, instance.clone(), rx))

//              Instance(instance, Arc::new(tx))
//          }

//          async fn run<R: Resolver>(resolver: R, purser: Purser, instance: Arc<ArcSwap<contract::Instance<C>>>, rx: Rx<mpsc::List<(C::Message, AsyncRx<spsc::One<C::Result>>)>>) {
//              //1. start by making a request
//              //2. listen for response and new sends
//              //3. update instance and request after proccessing a send and respond with result
//              //4. update the database
//          }

//          pub fn pending(&self) -> &C {self.0.pending()}
//          pub fn confirmed(&self) -> &C {self.0.confirmed()}

//          pub fn send(&self, message: C::Message) -> C::Result {
//              let (sp, sc) = spsc::build(spsc::One::new());
//              self.1.send((message, sp)).unwrap();
//              sc.recv().unwrap()
//          }

//          pub fn share(&self, name: Name) {
//          }
//      }

//      pub struct Instances<C: Contract>(Arc<HashMap<Id, Instance<C>>>);
//      impl Deref for Instances {
//          type Target = HashMap<Id, Instance<C>>;
//          fn deref(&self) -> &Self::Target {&self.0}
//      }
//  impl<C: Contract> Instances<C> {
//      pub fn create<C: Contract>(&self) -> Instance<C> {
//      }
//  }

//  pub struct Context(Contracts, Tx);
//  impl Context {
//      pub fn register<C: Contract>(&mut self) {
//          self.2.register::<C>();
//      }

//      pub fn create<C: Contract>(&self, id: Id) -> Instance<C> {
//          //1. Step one is ensure a thread is setup to handle C
//          //2. Then I need to some how identify each instance to create or recover
//          //3. If creating I then need to spin up a thread for that instance as well
//          //
//          //
//          //For now use the latest harden keys,
//          //
//          //Instances can be identified with Ids

//      }

//      pub fn instances<C: Contract>(&self) -> Instances<C> {

//      }
//  }




//  pub struct Contracts(Arc<ArcSwap<HashMap<Id, Box<dyn Any + Send + Sync>>>>);
//  impl Contracts {
//      pub fn get<C: Contract>(&self) -> &Instances<C> {}
//      pub fn get_mut<C: Contract>(&mut self) -> &mut Instances<C> {}

//  }





//  #[derive(Clone)]
//  pub struct Runtime {
//      handle: tokio::runtime::Handle,
//      token: CancellationToken,
//      tasks: TaskTracker,
//      resolver: Resolver,
//  }
//  impl Runtime {
//      pub fn new() -> Self {
//          let runtime = tokio::runtime::Builder::new_multi_thread().enable_time().enable_io().build().unwrap();
//          let _guard = runtime.enter();
//          let resolver = names::Resolver::start();

//          let token = CancellationToken::new();
//          let tasks = TaskTracker::new();
//          let air = Air{
//              handle: runtime.handle().clone(),
//              token: token.clone(),
//              tasks: tasks.clone(),
//              resolver,
//          };

//          std::thread::spawn(move || runtime.block_on(async move {
//              token.cancelled().await;
//              tasks.wait().await;
//          }));

//          air 
//      }

//      pub fn spawn<F: Future<Output = ()> + Send + 'static>(&self, future: F) {
//          self.tasks.spawn_on(future, &self.handle);
//      }

//      pub fn shutdown(self) {
//          self.token.cancel();
//          self.tasks.close();
//          self.handle.clone().block_on(self.tasks.wait());
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

//  pub type Receiver = Box<dyn Fn(&mut dyn Any, Location)>;
//  pub type Requester = Box<dyn Fn(&mut dyn Any, &Secret) -> Result<HashMap<Id, Request>, Error>>;

//  pub struct ErasedContract(Receiver, Requester, Box<dyn Any>);
//  impl ErasedContract {
//      pub fn new<C: Contract>(name: Name) -> Self {
//          ErasedContract(
//              Box::new(move |any, location| any.downcast_mut::<Instances<C>>().unwrap().receive(name, location)),
//              Box::new(move |any, secret| any.downcast_mut::<Instances<C>>().unwrap().request(secret)),
//              Box::new(Instances::<C>::default())
//          )
//      }
//  }

//  pub struct Contracts(HashMap<Id, ErasedContract>, Name);
//  impl Contracts {
//      pub fn new(name: Name) -> Self {Contracts(HashMap::new(), name)}
//      pub fn register<C: Contract>(&mut self) -> &mut Instances<C> {
//          self.0.entry(C::id()).or_insert_with(|| ErasedContract::new::<C>(self.1)).2.downcast_mut().unwrap()
//      }
//  }
