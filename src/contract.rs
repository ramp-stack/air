use crate::names::{Id, Secret, Name, now};

use crate::channel::{Distributable, Channel, Location, Event, Change};

use std::collections::VecDeque;
use std::hash::Hash;
use std::fmt::Debug;

use serde::{Serialize, Deserialize};

#[derive(Clone, Debug, Copy)]
pub struct Metadata {
    pub signer: Name,
    pub timestamp: u64,
    pub confirmed: bool
}
impl Metadata {
    fn pending(signer: Name) -> Self {Metadata{signer, timestamp: now(), confirmed: false}}
    fn confirmed(signer: Name, timestamp: u64) -> Self {Metadata{signer, timestamp, confirmed: true}}
}

pub trait Contract: Serialize + for<'a> Deserialize<'a> + Hash + Debug + Clone + Send + Sync + 'static {
    type Init: Serialize + for<'a> Deserialize<'a> + Hash + Debug + Unpin + Clone + Send + Sync;
    type Message: Serialize + for<'a> Deserialize<'a> + Hash + Debug + Unpin + Clone + Send + Sync;
    
    fn id() -> Id;

    fn init(init: Self::Init, metadata: Metadata) -> Self;
    fn apply(&mut self, message: Self::Message, metadata: Metadata);
}

#[derive(Serialize, Deserialize, Clone, Debug, Hash)]
pub enum Message<C: Contract> { Init(C::Init), Message(C::Message) }

#[derive(Debug, Clone, Copy)]
pub struct Changed {
    pending: bool,
    confirmed: bool,
    head: bool
}
impl Change for Option<Changed> {
    fn merge(self, other: Self) -> Self {match (self, other) {
        (Some(left), Some(right)) => Some(Changed{
            pending: left.pending | right.pending,
            confirmed: left.confirmed | right.confirmed,
            head: left.head | right.head,
        }),
        (left, right) => left.or(right),
    }}
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(bound = "C: Contract")]
pub struct Instance<C: Contract> {
    pub confirmed: Option<C>,
    pub pending: Option<C>,//Pending can never be none if its created by me. I want to refeuse to
    //revieal this contract exists untill It gets a pending if received none from someone else.
    pub head: bool,
}
impl<C: Contract> Instance<C> {
    pub fn new(secret: &Secret, init: C::Init) -> Channel<Self> {
        let path = vec![Id::hash(&"CONTRACTS"), C::id()];
        
        let location = Location {
            key: secret.derive(&path).harden(),
            path,
            server: Name::orange_me()
        };
        let mut channel = Channel::<Instance<C>>::new(secret.name(), location);
        channel.apply(Message::Init(init));
        channel
    }

    pub fn pending(&self) -> &C {self.pending.as_ref().unwrap()}
    pub fn confirmed(&self) -> Option<&C> {self.confirmed.as_ref()}
    pub fn at_head(&self) -> bool {self.head}
}
impl<C: Contract> Distributable for Instance<C> {
    type Message = Message<C>;
    type Change = Option<Changed>;

    fn apply(&mut self, me: &Name, queue: &VecDeque<Message<C>>, event: Event<Message<C>>) -> Option<Changed> {match (self, queue.back(), event) {
        (Self{pending, ..}, Some(Message::Init(c_init)), Event::Pending) if pending.is_none() => {
            *pending = Some(C::init(c_init.clone(), Metadata::pending(*me)));
            Some(Changed{confirmed: false, pending: true, head: false})
        },
        (Self{confirmed, pending, ..}, _, Event::Confirmed(Message::Init(c_init), name, time)) if confirmed.is_none() => {
            let mut init = C::init(c_init, Metadata::confirmed(time, name));
            *confirmed = Some(init.clone());
            for msg in queue {if let Message::Message(msg) = msg {
                init.apply(msg.clone(), Metadata::pending(*me));
            }}
            *pending = Some(init);
            Some(Changed{confirmed: true, pending: true, head: false})
        },
        (Self{pending: Some(pending), ..}, Some(Message::Message(msg)), Event::Pending) => {
            pending.apply(msg.clone(), Metadata::pending(*me));
            Some(Changed{confirmed: false, pending: true, head: false})
        },
        (Self{confirmed: Some(confirmed), pending: Some(pending), ..}, _, Event::Confirmed(Message::Message(msg), name, time)) => {
            confirmed.apply(msg, Metadata::confirmed(time, name));
            *pending = confirmed.clone();
            for msg in queue {if let Message::Message(msg) = msg {
                pending.apply(msg.clone(), Metadata::pending(*me));
            }}
            Some(Changed{confirmed: true, pending: true, head: false})
        },
        (Self{head, ..}, _, Event::Empty(_)) if !*head => {
            *head = true;
            Some(Changed{confirmed: false, pending: false, head: true})
        }
        tuple => {println!("Ignored Message: {:?}", tuple); None}
    }}
}
impl<C: Contract> Default for Instance<C> {fn default() -> Self {
    Self{confirmed: None, pending: None, head: false}
}}












//  #[derive(Clone)]
//  pub struct Instance<C: Contract>(Shared<Snapshot<C>>, bool, bool, bool);
//  impl<C: Contract> Debug for Instance<C> {fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {self.0.load().fmt(f)}}
//  impl<C: Contract> Instance<C> {
//      fn new(air: Air, location: Location) -> Self {Instance(Shared::new(air, location))}
//      fn location(&self) -> &Location {self.0.location()}

//      pub fn id(&self) -> Id {Id::hash(self.location())}
//      pub fn is_head(&self) -> bool {self.3}
//      pub async fn head(&self) {}


//      ///Clears updates
//      pub fn load_pending(&self) -> Ref<'_, C> {}
//      pub fn load_confirmed(&self) -> Ref<'_, C> {}

//      pub fn pending_changed(&self) -> Option<Ref<'_, C>> {}
//      pub fn confirmed_changed(&self) -> Option<Ref<'_, C>> {}

//      pub async fn listen_pending(&self) -> Ref<'_, C> {}
//      pub async fn listen_confirmed(&self) -> Ref<'_, C> {}

//      pub fn apply(&mut self, message: C::Message) {self.0.apply(Message::Message(message));}
//      pub fn share(&self, name: Name) {self.0.share(name)}
//  }

//  pub type Erased = Arc<Box<dyn Any + Send + Sync>>;

//  pub struct Context {
//      contracts: Ams<HashMap<Id, Erased>, ()>,
//      air: Air
//  }
//  impl Context {
//      pub fn register<C: Contract>(&self) {self._register::<C>();}
//      pub fn instances<C: Contract>(&self) -> Instances<C> {Instances(HashMap::new(), self._register::<C>)}
//      pub fn create<C: Contract>(&self, init: C::Init) -> Instance<C> {
//          let path = vec![C::id(), Id::hash(&init)];
//          let key = self.air.secret.derive(&path).harden();
//          let location = Location::new(path, key);
//          let id = Id::hash(&location);
//          let locations = self._register::<C>();
//          //TODO: I should be able to choose against receiving this instance
//          let mut instance = match locations.apply(location) {//I could make this a pending action
//              Some(mut i) => i.pop().unwrap(),
//              None => locations.load().instances.get(&id).unwrap().clone()
//          };
//          instance.0.apply(Message::Init(init));//If init has already happend this will do nothing see Snapshot::Sharable
//          instance
//      }

//      fn _register<C: Contract>(&self) -> Shared<Locations<C>> {
//          self.contracts.load().get(&id).or_else(|| {
//              let lock = self.contracts.lock();
//              let entry = lock.entry(id);
//              match lock.entry(id) {
//                  Entry::Occupied(ocu) => ocu.get().downcast_ref().unwrap(),
//                  Entry::Vacent(vac) => {
//                      let locations = Locations::new(self.air.clone());
//                      vac.insert(Arc::new(Box::new(locations.clone())));
//                      lock.commit(());
//                      locations
//                  }
//              }
//          })
//      }
//  }

//  #[derive(Serialize, Deserialize, Clone, Debug)]
//  #[serde(bound = "C: Contract")]
//  pub struct Locations<C: Contract> {
//      locations: HashMap<Id, Location>,
//      #[serde(skip)]
//      instances: HashMap<Id, Instance<C>>,
//  }
//  impl<C: Contract> Locations<C> {
//      pub fn new(air: Air) -> Shared<Self> {
//          let path = vec![C::id()];
//          let key = air.secret.derive(&path).harden();
//          Shared::new(air, Location::new(path, key))
//      }
//  }
//  impl<C: Contract> Default for Locations<C> {fn default() -> Self {Locations{locations: HashMap::new(), instances: HashMap::new()}}}
//  impl<C: Contract> Sharable for Locations<C> {
//      type Message = Location;
//      type Changed = Vec<Instance<C>>;

//      fn on_event(&mut self, air: &Air, event: Event<Self::Message>) -> Option<Self::Changed> {
//          if matches!(event, Event::Start) {
//              self.instances = self.locations.values().map(|l| (Id::hash(&l), Instance::new(air.clone(), l.clone()))).collect();
//              Some(self.instances.values().cloned().collect())
//          } else if let Event::Pending(location) | Event::NewConfirmed(location, _, _) = event {
//              let id = Id::hash(&location);
//              let is_new = self.locations.insert(id, location.clone()).is_none();
//              let instance = self.instances.entry(id).or_insert_with(|| Instance::new(air.clone(), location));
//              is_new.then_some(vec![instance.clone()])
//          } else {None}
//      }
//  }

//  pub struct Instances<C>(HashMap<Id, Instance<C>>, Shared<Locations<C>>);

//  impl<C: Contract> Deref for Instances<C> {type Target = HashMap<Id, Instance<C>>; fn deref(&self) -> Self::Target {&self.0}}
//  impl<C: Contract> Instances<C> {
//      ///Gets all new Instances and makes them available to deref
//      pub fn reload(&mut self) {}

//      pub fn get_new(&mut self) -> Vec<&Instance<C>> {}
//      pub async fn listen(&mut self) -> Vec<&Instance<C>> {}
//  }












//  pub struct ErasedReactant<C>(Box<dyn Fn(&mut C, Metadata) + Send + Sync>);
//  impl<C: Contract> ErasedReactant<C> {
//      pub fn new<R: Reactant<C>>(reactant: R) -> Self {
//          ErasedReactant(Box::new(move |contract: &mut C, metadata: Metadata| reactant.clone().apply(contract, metadata)))
//      }
//  }

//  #[derive(Default)]
//  pub struct Reactants<C: Contract>(BTreeMap<Id, Box<dyn Fn(Vec<u8>) -> Option<ErasedReactant<C>>>>);
//  impl<C: Contract> Reactants<C> {
//      pub fn add<R: Reactant<C>>(mut self) -> Self {
//          self.0.insert(R::id(), Box::new(move |b: Vec<u8>| postcard::from_bytes::<R>(b).ok().map(ErasedReactant::new)));
//          self
//      } 
//      fn contains<R: Reactant<C> + 'static>(&self) -> bool {self.0.contains(R::id())}
//      fn deserilize(&self, id: &Id, bytes: Vec<u8>) -> Option<ErasedReactant<C>> {
//          match self.0.get(id) {
//              Some(deserialize) => (deserialize)(bytes),
//              None => {println!("Unknown Reactant {:?}", id); None}
//          }
//      }
//  }

//  pub struct Manager {
//       
//  }
//  impl Manager {
//      pub fn start(air: Air) -> Context {

//      }
//  }

//  pub struct Manager {
//      context: Context,
//      store: Box<dyn Store>,
//      root: Root,
//      inbox: InboxHandler,
//      joinset: JoinSet<(Id, Stream, u64, Event)>,
//      sinks: BTreeMap<Id, Sink>,
//  }

//  impl Manager {
//      pub fn start(air: Air, store: impl Store + 'static) -> Context {
//          let cache = Cache::new(format!("./{}/{}.db", air.name, air.name)).unwrap();
//          let root = cache.get::<Root>("root").unwrap().unwrap_or_default();

//          let inbox = root.inbox.start(air.clone());
//          let contracts = Contracts(Ams::new(BTreeMap::new()), Ams::new(BTreeMap::new()), air.clone());
//          let i = contracts.clone();

//          air.handle.clone().spawn(async move {
//              let mut manager = Manager{sinks: BTreeMap::new(), cache, root, inbox, joinset: JoinSet::new(), contracts};
//              let keys = manager.root.contracts.keys().copied().collect::<Vec<_>>();
//              for id in keys {
//                  manager.register(id);
//              }
//              manager.run().await
//          });
//          i
//      }

//      fn register(&mut self, id: Id) -> &mut HashSet<Location> {
//          let air = self.contracts.2.clone();
//          let secret = air.secret.derive(&[id]);
//          let entry = self.root.contracts.entry(id).or_insert_with(|| {
//              let channel = Channel::new(secret.harden());
//              (channel, HashSet::default())
//          });
//          self.sinks.entry(id).or_insert_with(|| {
//              let (mut stream, sink) = entry.0.start(air, secret);
//              self.joinset.spawn(async move {
//                  let (time, namedata) = stream.read().await;
//                  (id, stream, time, namedata)
//              });
//              sink
//          });
//          &mut entry.1
//      }

//      async fn store(&mut self, location: Location, write: bool) {
//          let locations = self.register(location.contract_id);
//          if locations.insert(location) {
//              let sink = self.sinks.get(&location.contract_id).unwrap();
//              if write {sink.write(postcard::to_allocvec(&location).unwrap()).await;}
//          }
//      }

//      async fn run(mut self) {
//          loop {
//              tokio::select!{ biased;
//                  c_id = self.contracts.1.listen() => {
//                      for location in self.register(c_id).iter().copied().collect::<Vec<_>>() { 
//                          self.contracts.build(location).expect("False Register");
//                      }
//                  },
//                  instance = self.contracts.0.listen() => {self.store(instance.1, true).await},
//                  (_, location) = self.inbox.read() => {
//                      self.root.inbox = *self.inbox.inbox();
//                      if let Some(location) = location.and_then(|l| postcard::from_bytes(&l).ok()) {
//                          self.store(location, true).await;
//                          self.contracts.build(location);
//                      }
//                  },
//                  Some(Ok((id, mut stream, _, event))) = self.joinset.join_next() => {
//                      self.root.contracts.get_mut(&id).unwrap().0 = *stream.channel();

//                      if let Event::Data(_, data, _) = event 
//                      && let Ok((contract_hash, key)) = postcard::from_bytes::<(Id, SecretKey)>(&data) {
//                          let location = Location{key, contract_id: id, contract_hash};
//                          self.store(location, false).await;
//                          self.contracts.build(location);
//                      }

//                      self.joinset.spawn(async move {
//                          let (time, namedata) = stream.read().await;
//                          (id, stream, time, namedata)
//                      });
//                  },
//                  else => {}
//              }           
//              self.cache.insert("root", &self.root).unwrap();
//          }
//      }
//  }


//  #[derive(Clone)]
//  pub struct Instance<C: Contract>{
//      id: Id,
//      air: Air,
//      sink: Sink,
//      location: Location,
//      reactants: Arc<Reactants<C>>,
//      confirmed: Ams<Option<C>, AnyOutput<C>>,
//      pending_queue: Arc<Mutex<VecDeque<PendingReactant<C>>>>,
//      pending: Ams<Option<C>, ()>,
//      head: Ams<bool, bool>
//  }

//  impl<C: Contract> std::fmt::Debug for Instance<C> {fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
//      f.debug_struct("Instance").field("id", &self.id).field("confirmed", &self.confirmed).field("pending", &self.pending).finish()
//  }}

//  impl<C: Contract> Instance<C> {
//      pub fn id(&self) -> Id {self.id}

//      fn start(air: Air, location: Location, init: Option<C::Init>) -> Self {
//          let id = Id::hash(&location);
//          let cache = Cache::new(format!("{}/{}/{}", air.name, C::id(), id)).unwrap();
//          let secret = air.secret.derive(&[C::id(), id]);
//          let (channel, contract) = cache.get::<(Channel, Option<C>)>("instance").unwrap().unwrap_or((Channel::new(location.key), None));
//          let (stream, sink) = channel.start(air.clone(), secret);
//          if let Some(init) = init.as_ref() && contract.is_none() {
//              sink.write_sync(postcard::to_allocvec(&(id, postcard::to_allocvec(init).unwrap())).unwrap());
//          }
//          let contract = contract.or(init.map(|i| C::init(i, Metadata::pending(air.name))));
//          let reactants = Arc::new(C::reactants());
//          let confirmed = Ams::new(contract.clone());
//          let pending_queue = Arc::new(Mutex::new(VecDeque::new()));
//          let pending = Ams::new(contract);
//          let head = Ams::new(false);
//          let instance = Instance{sink, air: air.clone(), id, location, reactants, confirmed, pending_queue, pending, head};
//          air.handle.spawn(instance.clone().run(cache, stream));
//          instance
//      }

//      pub fn share(&self, name: Name) {
//          InboxHandler::send(self.air.clone(), name, postcard::to_allocvec(&self.location).unwrap());
//      }

//      pub fn get_update(&mut self) -> Option<Changed<C>> {
//          self.confirmed.get_update().map(Changed::Confirmed).or(self.pending.get_update().map(|_| Update::Pending))
//      }

//      pub async fn listen(&mut self) -> Changed<C> {
//          tokio::select!{
//              output = self.confirmed.listen() => Changed::Confirmed(output),
//              _ = self.pending.listen() => Changed::Pending
//          }
//      }

//      ///If the outer result is Err the reactant has not been sent and will not update its state in the future
//      pub fn try_apply<O: Send + Sync + Clone + Debug, E: Sync + Send + Clone + Debug, R: Reactant<C, Output = Result<O, E>>>(&mut self, reactant: R) -> PendingResult<C, O, E, R> {
//          let id = self.reactants.id::<R>().expect("Reactant is not listed in Contract::reactants()");
//          let mut pending = self.pending.lock();
//          let mut queue = self.pending_queue.lock().unwrap();
//          let metadata = Metadata::pending(self.air.name);
//          match reactant.clone().apply(pending.as_mut().unwrap(), metadata) {
//              Err(e) => PendingResult::Err(e),
//              Ok(output) => {
//                  let output = Pending::new(Ok(output));
//                  let id = self.sink.write_sync(postcard::to_allocvec(&(id, postcard::to_allocvec(&reactant).unwrap())).unwrap());
//                  let reactant = PendingReactant::new(id, reactant, output.clone());
//                  queue.push_back(reactant);
//                  pending.commit(());
//                  PendingResult::Ok(output)
//              }
//          }
//      }

//      pub fn apply<R: Reactant<C>>(&mut self, reactant: R) -> Pending<C, R> {
//          let id = self.reactants.id::<R>().expect("Reactant is not listed in Contract::reactants()");
//          let mut pending = self.pending.lock();
//          let mut queue = self.pending_queue.lock().unwrap();
//          let metadata = Metadata::pending(self.air.name);
//          let output = Pending::new(reactant.clone().apply(pending.as_mut().unwrap(), metadata));
//          let id = self.sink.write_sync(postcard::to_allocvec(&(id, postcard::to_allocvec(&reactant).unwrap())).unwrap());
//          let reactant = PendingReactant::new(id, reactant, output.clone());
//          queue.push_back(reactant);
//          pending.commit(());
//          output
//      }

//      async fn run(mut self, mut cache: Cache, mut stream: Stream) {
//          loop {
//              let (timestamp, event) = stream.read().await;
//              match event {
//                  Event::Head => {
//                      let mut lock = self.head.lock();
//                      *lock = true;
//                      lock.commit(true);
//                  },
//                  Event::Data(signer, data, rid) => {
//                      if let Ok((id, bytes)) = postcard::from_bytes::<(Id, Vec<u8>)>(&data) {
//                          let metadata = Metadata::confirmed(signer, timestamp);
//                          if self.confirmed.load().is_none() {
//                              if id == self.id && let Ok(init) = postcard::from_bytes(&bytes) {
//                                  let mut confirmed = self.confirmed.lock();
//                                  *confirmed = Some(C::init(init, metadata));
//                                  confirmed.commit_silent();
//                              } else {
//                                  println!("Invalid Contract Init");
//                              }
//                          } else if id == self.id {
//                              println!("Found Contract Init Again(ignoring)");
//                          } else {
//                              let mut pending = self.pending.lock();
//                              let mut queue = self.pending_queue.lock().unwrap();
//                              let mut confirmed = self.confirmed.lock();
//                              let mut reorg = false;

//                              let output = if let Some(rid) = rid && queue.front().map(|pending| pending.0 == rid).unwrap_or_default() {
//                                  Some(queue.pop_front().unwrap().apply(confirmed.as_mut().unwrap(), metadata))
//                              } else {
//                                  reorg = !queue.is_empty();
//                                  self.reactants.apply(&id, bytes, confirmed.as_mut().unwrap(), metadata)
//                              };

//                              if let Some(output) = output {
//                                  *pending = confirmed.clone();
//                                  for reactant in &mut *queue {
//                                      reactant.apply(pending.as_mut().unwrap(), Metadata::pending(self.air.name));
//                                  }
//                                  if !reorg {pending.commit_silent();} else {pending.commit(());}
//                                  confirmed.commit(output);
//                              }
//                          }
//                      }
//                  },
//                  Event::Garbage => {}
//              }
//              cache.insert("instance", &(&stream.channel(), &*self.confirmed.load())).unwrap();
//          }
//      }

//      pub fn is_near_head(&mut self) -> bool {*self.head.load()}
//      pub async fn head(&mut self) {
//          loop { if *self.head.load() {break;} self.head.listen().await;}
//      }
//  }




































//  #[derive(Clone)]
//  pub struct AnyInstance(Arc<Box<dyn Fn() -> Box<dyn Any + Send + Sync> + Send + Sync>>, Location);
//  impl Debug for AnyInstance {fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {f.debug_tuple("AnyInstance").field(&self.1).finish()}}
//  impl AnyInstance {
//      pub fn new<C: Contract>(instance: Instance<C>) -> Self {
//          let location = instance.location;
//          AnyInstance(Arc::new(Box::new(move || Box::new(instance.clone()))), location)
//      }
//      pub fn downcast<C: Contract>(&self) -> Option<Instance<C>> {
//          (self.0)().downcast::<Instance<C>>().ok().map(|i| *i)
//      }
//  }

//  #[derive(Clone)]
//  pub struct AnyOutput<C: Contract>(Arc<Box<dyn Fn() -> Box<dyn Any + Send + Sync> + Send + Sync>>, TypeId, PhantomData<C>, String);
//  impl<C: Contract> Debug for AnyOutput<C> {fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {f.debug_tuple("AnyOutput").field(&self.3).finish()}}

//  impl<C: Contract> AnyOutput<C> {
//      pub fn new<R: Reactant<C>>(output: R::Output) -> Self {
//          let debug = format!("{:?}", output);
//          AnyOutput(Arc::new(Box::new(move || Box::new(output.clone()))), TypeId::of::<R>(), PhantomData::<C>, debug)
//      }
//      pub fn downcast<R: Reactant<C>>(&self) -> Option<R::Output> {
//          (TypeId::of::<R>() == self.1).then(|| *(self.0)().downcast::<R::Output>().unwrap())
//      }
//  }

//  pub enum PendingResult<C: Contract, O: Clone + Send + Sync + 'static, E: Clone + Send + Sync + 'static, R: Reactant<C, Output = Result<O, E>>> {
//      Ok(Pending<C, R>),
//      Err(E)
//  }
//  impl<C: Contract, O: Clone + Send + Sync + 'static, E: Clone + Send + Sync + 'static, R: Reactant<C, Output = Result<O, E>>> PendingResult<C, O, E, R> {
//      pub async fn confirmed(self) -> Result<O, E> {match self {
//          Self::Ok(pending) => pending.confirmed().await.clone(),
//          Self::Err(e) => Err(e)
//      }}
//  }

//  #[derive(Clone, Debug, PartialEq)]
//  pub struct Pending<C: Contract, R: Reactant<C>>(Ams<(R::Output, bool), bool>);
//  impl<C: Contract, R: Reactant<C>> Pending<C, R> {
//      fn new(output: R::Output) -> Self {Pending(Ams::new((output, false)))}

//      pub fn is_confirmed(&mut self) -> bool {self.0.load().1}
//      pub fn load(&mut self) -> Ref<R::Output> {self.0.load_partial(|r| &r.0)}
//      pub fn get_update(&mut self) -> Option<bool> {self.0.get_update()}
//      pub async fn confirmed(mut self) -> Ref<R::Output> {
//          loop {if self.0.listen().await {break self.load()}}
//      }

//      fn update(&mut self, output: R::Output, confirmed: bool) {
//          let mut lock = self.0.lock();
//          *lock = (output, confirmed);
//          lock.commit(confirmed);
//      }
//  }

//  type Apply<C> = Box<dyn FnMut(&mut C, Metadata) -> AnyOutput<C> + Send + Sync>;

//  pub struct PendingReactant<C: Contract>(Id, Apply<C>);
//  impl<C: Contract> Debug for PendingReactant<C> {fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
//      f.debug_tuple("PendingReactant").field(&self.0).finish()
//  }}
//  impl<C: Contract> PendingReactant<C> {
//      pub fn new<R: Reactant<C>>(id: Id, reactant: R, mut pending: Pending<C, R>) -> Self {
//          PendingReactant(id, Box::new(move |contract: &mut C, metadata: Metadata| {
//              let output = reactant.clone().apply(contract, metadata);
//              pending.update(output.clone(), metadata.confirmed);
//              AnyOutput::new::<R>(output)
//          }))
//      }
//      pub fn apply(&mut self, contract: &mut C, metadata: Metadata) -> AnyOutput<C> {
//          (self.1)(contract, metadata)
//      }
//  }

//  #[derive(Clone)]
//  pub struct Instance<C: Contract>{
//      id: Id,
//      air: Air,
//      sink: Sink,
//      location: Location,
//      reactants: Arc<Reactants<C>>,
//      confirmed: Ams<Option<C>, AnyOutput<C>>,
//      pending_queue: Arc<Mutex<VecDeque<PendingReactant<C>>>>,
//      pending: Ams<Option<C>, ()>,
//      head: Ams<bool, bool>
//  }

//  impl<C: Contract> std::fmt::Debug for Instance<C> {fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
//      f.debug_struct("Instance").field("id", &self.id).field("confirmed", &self.confirmed).field("pending", &self.pending).finish()
//  }}

//  impl<C: Contract> Instance<C> {
//      pub fn id(&self) -> Id {self.id}

//      fn start(air: Air, location: Location, init: Option<C::Init>) -> Self {
//          let id = Id::hash(&location);
//          let cache = Cache::new(format!("{}/{}/{}", air.name, C::id(), id)).unwrap();
//          let secret = air.secret.derive(&[C::id(), id]);
//          let (channel, contract) = cache.get::<(Channel, Option<C>)>("instance").unwrap().unwrap_or((Channel::new(location.key), None));
//          let (stream, sink) = channel.start(air.clone(), secret);
//          if let Some(init) = init.as_ref() && contract.is_none() {
//              sink.write_sync(postcard::to_allocvec(&(id, postcard::to_allocvec(init).unwrap())).unwrap());
//          }
//          let contract = contract.or(init.map(|i| C::init(i, Metadata::pending(air.name))));
//          let reactants = Arc::new(C::reactants());
//          let confirmed = Ams::new(contract.clone());
//          let pending_queue = Arc::new(Mutex::new(VecDeque::new()));
//          let pending = Ams::new(contract);
//          let head = Ams::new(false);
//          let instance = Instance{sink, air: air.clone(), id, location, reactants, confirmed, pending_queue, pending, head};
//          air.handle.spawn(instance.clone().run(cache, stream));
//          instance
//      }

//      pub fn share(&self, name: Name) {
//          InboxHandler::send(self.air.clone(), name, postcard::to_allocvec(&self.location).unwrap());
//      }

//      pub fn confirmed_update(&mut self) -> Option<AnyOutput<C>> {self.confirmed.get_update()}
//      pub async fn listen_confirmed(&mut self) -> AnyOutput<C> {self.confirmed.listen().await}
//      pub fn load_confirmed(&mut self) -> Ref<C> {self.confirmed.load_partial(|c| c.as_ref().unwrap())}
//      pub fn pending_updated(&mut self) -> bool {self.pending.get_update().is_some()}
//      pub async fn listen_pending(&mut self) {self.pending.listen().await}
//      pub fn load_pending(&mut self) -> Ref<C> {self.pending.load_partial(|i| i.as_ref().unwrap())}

//      pub fn get_update(&mut self) -> Option<Changed<C>> {
//          self.confirmed.get_update().map(Changed::Confirmed).or(self.pending.get_update().map(|_| Update::Pending))
//      }

//      pub async fn listen(&mut self) -> Changed<C> {
//          tokio::select!{
//              output = self.confirmed.listen() => Changed::Confirmed(output),
//              _ = self.pending.listen() => Changed::Pending
//          }
//      }

//      ///If the outer result is Err the reactant has not been sent and will not update its state in the future
//      pub fn try_apply<O: Send + Sync + Clone + Debug, E: Sync + Send + Clone + Debug, R: Reactant<C, Output = Result<O, E>>>(&mut self, reactant: R) -> PendingResult<C, O, E, R> {
//          let id = self.reactants.id::<R>().expect("Reactant is not listed in Contract::reactants()");
//          let mut pending = self.pending.lock();
//          let mut queue = self.pending_queue.lock().unwrap();
//          let metadata = Metadata::pending(self.air.name);
//          match reactant.clone().apply(pending.as_mut().unwrap(), metadata) {
//              Err(e) => PendingResult::Err(e),
//              Ok(output) => {
//                  let output = Pending::new(Ok(output));
//                  let id = self.sink.write_sync(postcard::to_allocvec(&(id, postcard::to_allocvec(&reactant).unwrap())).unwrap());
//                  let reactant = PendingReactant::new(id, reactant, output.clone());
//                  queue.push_back(reactant);
//                  pending.commit(());
//                  PendingResult::Ok(output)
//              }
//          }
//      }

//      pub fn apply<R: Reactant<C>>(&mut self, reactant: R) -> Pending<C, R> {
//          let id = self.reactants.id::<R>().expect("Reactant is not listed in Contract::reactants()");
//          let mut pending = self.pending.lock();
//          let mut queue = self.pending_queue.lock().unwrap();
//          let metadata = Metadata::pending(self.air.name);
//          let output = Pending::new(reactant.clone().apply(pending.as_mut().unwrap(), metadata));
//          let id = self.sink.write_sync(postcard::to_allocvec(&(id, postcard::to_allocvec(&reactant).unwrap())).unwrap());
//          let reactant = PendingReactant::new(id, reactant, output.clone());
//          queue.push_back(reactant);
//          pending.commit(());
//          output
//      }

//      async fn run(mut self, mut cache: Cache, mut stream: Stream) {
//          loop {
//              let (timestamp, event) = stream.read().await;
//              match event {
//                  Event::Head => {
//                      let mut lock = self.head.lock();
//                      *lock = true;
//                      lock.commit(true);
//                  },
//                  Event::Data(signer, data, rid) => {
//                      if let Ok((id, bytes)) = postcard::from_bytes::<(Id, Vec<u8>)>(&data) {
//                          let metadata = Metadata::confirmed(signer, timestamp);
//                          if self.confirmed.load().is_none() {
//                              if id == self.id && let Ok(init) = postcard::from_bytes(&bytes) {
//                                  let mut confirmed = self.confirmed.lock();
//                                  *confirmed = Some(C::init(init, metadata));
//                                  confirmed.commit_silent();
//                              } else {
//                                  println!("Invalid Contract Init");
//                              }
//                          } else if id == self.id {
//                              println!("Found Contract Init Again(ignoring)");
//                          } else {
//                              let mut pending = self.pending.lock();
//                              let mut queue = self.pending_queue.lock().unwrap();
//                              let mut confirmed = self.confirmed.lock();
//                              let mut reorg = false;

//                              let output = if let Some(rid) = rid && queue.front().map(|pending| pending.0 == rid).unwrap_or_default() {
//                                  Some(queue.pop_front().unwrap().apply(confirmed.as_mut().unwrap(), metadata))
//                              } else {
//                                  reorg = !queue.is_empty();
//                                  self.reactants.apply(&id, bytes, confirmed.as_mut().unwrap(), metadata)
//                              };

//                              if let Some(output) = output {
//                                  *pending = confirmed.clone();
//                                  for reactant in &mut *queue {
//                                      reactant.apply(pending.as_mut().unwrap(), Metadata::pending(self.air.name));
//                                  }
//                                  if !reorg {pending.commit_silent();} else {pending.commit(());}
//                                  confirmed.commit(output);
//                              }
//                          }
//                      }
//                  },
//                  Event::Garbage => {}
//              }
//              cache.insert("instance", &(&stream.channel(), &*self.confirmed.load())).unwrap();
//          }
//      }

//      pub fn is_near_head(&mut self) -> bool {*self.head.load()}
//      pub async fn head(&mut self) {
//          loop { if *self.head.load() {break;} self.head.listen().await;}
//      }
//  }

//  type Builder = Arc<Box<dyn Fn(Location) -> AnyInstance + Send + Sync>>;

//  #[derive(Clone)]
//  pub struct Contracts(Ams<BTreeMap<Id, BTreeMap<Id, AnyInstance>>, AnyInstance>, Ams<BTreeMap<Id, Builder>, Id>, Air);
//  impl Contracts {
//      pub fn register<C: Contract>(&self) {
//          let c_id = C::id();
//          let air = self.2.clone();
//          let mut builders = self.1.clone();
//          if !builders.load().contains_key(&c_id) {
//              let mut builders = builders.lock();
//              if let Entry::Vacant(vac) = builders.entry(c_id) {
//                  vac.insert(Arc::new(Box::new(move |location: Location| AnyInstance::new(Instance::<C>::start(air.clone(), location, None)))));
//                  builders.commit(c_id);
//              }
//          }
//      }

//      pub fn create<C: Contract>(&self, init: C::Init) -> Instance<C> {
//          self.register::<C>();
//          let c_id = C::id();
//          let location = Location::new::<C>(&self.2.secret, &init);
//          let id = Id::hash(&location);
//          let mut instances = self.0.clone();
//          match instances.load().get(&c_id).and_then(|i| i.get(&id)) {
//              Some(instance) => instance.downcast().unwrap(),
//              None => {
//                  let mut instances = instances.lock();
//                  match instances.entry(c_id).or_default().entry(id) {
//                      Entry::Occupied(occ) => occ.get().downcast().unwrap(),
//                      Entry::Vacant(vac) => {
//                          let instance = Instance::<C>::start(self.2.clone(), location, Some(init));
//                          let any = AnyInstance::new(instance.clone());
//                          vac.insert(any.clone());
//                          instances.commit(any);
//                          instance
//                      }
//                  }
//              }
//          }
//      }

//      fn build(&self, location: Location) -> Option<AnyInstance> {
//          let id = Id::hash(&location);
//          let mut instances = self.0.clone();
//          match instances.load().get(&location.contract_id).and_then(|i| i.get(&id)) {
//              Some(instance) => Some(instance.clone()),
//              None => {
//                  let mut instances = instances.lock();
//                  match instances.entry(location.contract_id).or_default().entry(id) {
//                      Entry::Occupied(occ) => Some(occ.get().clone()),
//                      Entry::Vacant(vac) => {
//                          let instance = (self.1.clone().load().get(&location.contract_id)?)(location);
//                          vac.insert(instance.clone());
//                          instances.commit(instance.clone());
//                          Some(instance) 
//                      }
//                  }
//              }
//          }
//      }

//      pub fn list<C: Contract>(&self) -> HashMap<Id, Instance<C>> {
//          match self.0.clone().load().get(&C::id()) {
//              None => {
//                  self.register::<C>();
//                  HashMap::new()
//              },
//              Some(instances) => instances.iter().filter_map(|(id, i)| {
//                  let mut instance = i.downcast::<C>().unwrap();
//                  if instance.pending.load().is_some() {
//                      Some((*id, instance.clone()))
//                  } else {None}
//              }).collect()
//          }
//      }
//  }

//  pub enum Changed<C: Contract> {NewInstance, Pending, Confirmed(AnyOutput<C>)}

//  pub struct Instances<C: Contract>(Contracts, HashMap<Id, Instance<C>>);
//  impl<C: Contract> Debug for Instances<C> {fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {f.debug_tuple("Instances").field(&self.1).finish()}}
//  impl<C: Contract> Instances<C> {
//      pub(crate) fn new(contracts: Contracts) -> Self {
//          contracts.register::<C>();
//          let instances = contracts.list();
//          Instances(contracts, instances)
//      }

//      pub fn create(&mut self, init: C::Init) -> &mut Instance<C> {
//          let instance = self.0.create::<C>(init);
//          self.1.entry(instance.id()).or_insert(instance)
//      }

//      pub async fn listen(&mut self) -> (&mut Instance<C>, Changed<C>) {
//          loop {
//              let mut set = self.1.values_mut().map(|i| async {(i.id(), i.listen().await)}).collect::<FuturesUnordered<_>>();
//              let new_instance = self.0.0.listen();
//              tokio::select!{
//                  instance = new_instance => {
//                      drop(set);
//                      if let Some(instance) = instance.downcast::<C>() {
//                          let instance = self.1.entry(instance.id()).or_insert(instance);
//                          return (instance, Changed::NewInstance);
//                      }
//                  },
//                  Some((id, update)) = set.next() => {
//                      drop(set);
//                      return (self.1.get_mut(&id).unwrap(), update)
//                  }
//              }
//          }
//      }

//      pub fn get_update(&mut self) -> Option<(&mut Instance<C>, Changed<C>)> {
//          match self.0.0.get_update() {
//              Some(instance) => instance.downcast::<C>().map(|instance| {
//                  let instance = self.1.entry(instance.id()).or_insert(instance);
//                  (instance, Changed::NewInstance)
//              }),
//              None => self.1.values_mut().find_map(|i| i.get_update().map(|u| (i, u)))
//          }
//      }
//  }

//  impl<C: Contract> std::ops::Deref for Instances<C> {
//      type Target = HashMap<Id, Instance<C>>;
//      fn deref(&self) -> &Self::Target {&self.1}
//  }
//  impl<C: Contract> std::ops::DerefMut for Instances<C> {
//      fn deref_mut(&mut self) -> &mut Self::Target {&mut self.1}
//  }

//  ///Keeps track of my Context and their locations for recovery, (Scanning my inbox, creating new
//  ///channels, storing and listening for new instances. Air never touches a contract Init
//  pub struct Manager {
//      contracts: Contracts,
//      cache: Cache,
//      root: Root,
//      inbox: InboxHandler,
//      joinset: JoinSet<(Id, Stream, u64, Event)>,
//      sinks: BTreeMap<Id, Sink>,
//  }

//  impl Manager {
//      pub fn start(air: Air) -> Contracts {
//          let cache = Cache::new(format!("./{}/{}.db", air.name, air.name)).unwrap();
//          let root = cache.get::<Root>("root").unwrap().unwrap_or_default();

//          let inbox = root.inbox.start(air.clone());
//          let contracts = Contracts(Ams::new(BTreeMap::new()), Ams::new(BTreeMap::new()), air.clone());
//          let i = contracts.clone();

//          air.handle.clone().spawn(async move {
//              let mut manager = Manager{sinks: BTreeMap::new(), cache, root, inbox, joinset: JoinSet::new(), contracts};
//              let keys = manager.root.contracts.keys().copied().collect::<Vec<_>>();
//              for id in keys {
//                  manager.register(id);
//              }
//              manager.run().await
//          });
//          i
//      }

//      fn register(&mut self, id: Id) -> &mut HashSet<Location> {
//          let air = self.contracts.2.clone();
//          let secret = air.secret.derive(&[id]);
//          let entry = self.root.contracts.entry(id).or_insert_with(|| {
//              let channel = Channel::new(secret.harden());
//              (channel, HashSet::default())
//          });
//          self.sinks.entry(id).or_insert_with(|| {
//              let (mut stream, sink) = entry.0.start(air, secret);
//              self.joinset.spawn(async move {
//                  let (time, namedata) = stream.read().await;
//                  (id, stream, time, namedata)
//              });
//              sink
//          });
//          &mut entry.1
//      }

//      async fn store(&mut self, location: Location, write: bool) {
//          let locations = self.register(location.contract_id);
//          if locations.insert(location) {
//              let sink = self.sinks.get(&location.contract_id).unwrap();
//              if write {sink.write(postcard::to_allocvec(&location).unwrap()).await;}
//          }
//      }

//      async fn run(mut self) {
//          loop {
//              tokio::select!{ biased;
//                  c_id = self.contracts.1.listen() => {
//                      for location in self.register(c_id).iter().copied().collect::<Vec<_>>() { 
//                          self.contracts.build(location).expect("False Register");
//                      }
//                  },
//                  instance = self.contracts.0.listen() => {self.store(instance.1, true).await},
//                  (_, location) = self.inbox.read() => {
//                      self.root.inbox = *self.inbox.inbox();
//                      if let Some(location) = location.and_then(|l| postcard::from_bytes(&l).ok()) {
//                          self.store(location, true).await;
//                          self.contracts.build(location);
//                      }
//                  },
//                  Some(Ok((id, mut stream, _, event))) = self.joinset.join_next() => {
//                      self.root.contracts.get_mut(&id).unwrap().0 = *stream.channel();

//                      if let Event::Data(_, data, _) = event 
//                      && let Ok((contract_hash, key)) = postcard::from_bytes::<(Id, SecretKey)>(&data) {
//                          let location = Location{key, contract_id: id, contract_hash};
//                          self.store(location, false).await;
//                          self.contracts.build(location);
//                      }

//                      self.joinset.spawn(async move {
//                          let (time, namedata) = stream.read().await;
//                          (id, stream, time, namedata)
//                      });
//                  },
//                  else => {}
//              }           
//              self.cache.insert("root", &self.root).unwrap();
//          }
//      }
//  }





//  #[derive(Serialize, Deserialize, Default, Debug)]
//  struct Root {
//      inbox: Inbox,
//      contracts: BTreeMap<Id, (Channel, HashSet<Location>)>,
//  }
