use easy_secp256k1::{EasySecretKey, EasyPublicKey};
use secp256k1::SecretKey;
use serde::{Serialize, Deserialize};

use std::collections::{VecDeque, BTreeMap, HashMap};
use std::sync::LazyLock;
use std::hash::{DefaultHasher, Hasher, Hash};
use std::fmt::Debug;
use std::task::Poll;
use std::any::TypeId;
use std::pin::pin;
use std::pin::Pin;

use crate::orange_name::{self, OrangeResolver, OrangeSecret, Endpoint};
use crate::Id;

use super::chandler::{Request, Response};
use super::{Client, ClientError};

use std::sync::{Arc, Mutex, MutexGuard};
use std::ops::DerefMut;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::sync::oneshot;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Hash)]
pub enum Error {
    MaliciousResponse(String),
    ConnectionFailed(String),
    CriticalOrange(String)
}
impl std::error::Error for Error {}
impl Error {pub(crate) fn mr(e: impl Debug) -> Self {Error::MaliciousResponse(format!("{e:?}"))}}
impl From<orange_name::Error> for Error {fn from(error: orange_name::Error) -> Self {match error{
    orange_name::Error::Critical(error) => {Error::CriticalOrange(error)}
    resolution => Error::ConnectionFailed(format!("{resolution:?}")),
}}}
impl From<ClientError> for Error {fn from(error: ClientError) -> Self {match error {
    ClientError::MaliciousResponse(response) => Error::MaliciousResponse(response),
    ClientError::ConnectionFailed(error) => Error::ConnectionFailed(error)
}}}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {write!(f, "{self:?}")}
}

pub struct Purser {
    client: Client,
}
impl Purser {
    pub fn new() -> Self {//secret: OrangeSecret) -> Self {
        Purser{client: Client}//, resolver: OrangeResolver, secret}//, multi_requests: BTreeMap::default()}
    }

    pub async fn send(&mut self, resolver: &mut OrangeResolver, recipient: &Endpoint, request: Request) -> Result<Response, Error> {
        let one_time_key = SecretKey::easy_new();
        let com = resolver.key(&recipient.0, Some("easy_access_com"), None).await?;
        let payload = com.easy_encrypt(serde_json::to_vec(&(one_time_key.easy_public_key(), &request)).unwrap()).unwrap();
        let response = self.client.send(recipient.1.as_str(), &payload).await?;
        serde_json::from_slice::<Response>(&one_time_key.easy_decrypt(&response).map_err(Error::mr)?).map_err(Error::mr)
    }

    pub async fn send_batch(&mut self, resolver: &mut OrangeResolver, requests: Vec<(Request, Vec<Endpoint>)>) -> Result<Vec<Vec<Response>>, Error> {
        let mut batches: BTreeMap<&Endpoint, Vec<Request>> = BTreeMap::new();
        requests.iter().for_each(|(r, es)| es.iter().for_each(|e| batches.entry(e).or_default().push(r.clone())));
        let mut results: BTreeMap<Endpoint, Vec<Response>> = BTreeMap::new();
        for (recipient, batch) in batches {
            results.insert(recipient.clone(), self.send(resolver, recipient, Request::batch(batch)).await?.batch()?);
        }
        Ok(requests.into_iter().rev().map(|(_, es)| es.into_iter().map(|e| results.get_mut(&e).unwrap().pop().unwrap()).collect()).collect())
    }
}

pub enum Status {
    Requests(Vec<(Request, Vec<Endpoint>)>),
    Finished(Box<dyn AnySend>)
}
impl Status {
    pub fn finished(res: impl AnySend + 'static) -> Self {
        Status::Finished(Box::new(res))
    }
}

pub trait AnySend: std::any::Any + Send + erased_serde::Serialize {}
impl<A: std::any::Any + Send + Serialize> AnySend for A {}
erased_serde::serialize_trait_object!(AnySend);

pub trait AnyError: AnySend + std::error::Error + erased_serde::Serialize {}
impl<E: AnySend + std::error::Error> AnyError for E {}
erased_serde::serialize_trait_object!(AnyError);

#[derive(Serialize, Deserialize)]
pub struct CommandResult(String);
impl CommandResult {
    pub fn to<C: Command + 'static>(self) -> Option<Result<C::Output, C::Error>> {
        serde_json::from_str(&self.0).ok()
    }
}

pub trait Command: AnySend + erased_serde::Serialize {
    type Output: Send + Serialize + for<'a> Deserialize<'a> where Self: Sized;
    type Error: AnyError + Serialize + for<'a> Deserialize<'a> where Self: Sized;
    fn run(self, ctx: Context) -> impl Future<Output = Result<Self::Output, Self::Error>> + Send where Self: Sized;
}
erased_serde::serialize_trait_object!(Command);

pub trait _Command {
    fn serialize(&self) -> Result<(u64, String), serde_json::Error>;
}

impl<C: Command> _Command for C {
    fn serialize(&self) -> Result<(u64, String), serde_json::Error> {
        println!("2");
        let mut hasher = DefaultHasher::new();
        TypeId::of::<C>().hash(&mut hasher);
        let mut writer = Vec::with_capacity(128);
        let mut serializer = serde_json::Serializer::new(writer);
        erased_serde::serialize(self, &mut serializer)?;
        unsafe {
            Ok((hasher.finish(), String::from_utf8_unchecked(serializer.into_inner())))
        }
    }
}

use serde::Serializer;
use serde::Deserializer;

pub trait AnyCommand: Send {
    fn run(self: Box<Self>, ctx: Context) -> Pin<Box<dyn Future<Output = Result<Box<dyn AnySend>, Box<dyn AnyError>>> + Send>>; 
    fn my_serialize(&self) -> Result<(u64, String), serde_json::Error>;
}

impl Serialize for Box<dyn AnyCommand> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        println!("0");
        match AnyCommand::my_serialize(self) {
            Err(e) => Err(serde::ser::Error::custom(e)),
            Ok(o) => Ok(o)
        }?.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Box<dyn AnyCommand> {
    fn deserialize<D: Deserializer<'de>>(mut deserializer: D) -> Result<Self, D::Error> {
        let (id, s) = <(u64, String)>::deserialize(deserializer)?;
        Ok(inventory::iter::<RegisteredCommand>().find_map(|RegisteredCommand(rc_id, des)|
                (id == rc_id()).then_some(des(&mut Box::new(<dyn erased_serde::Deserializer>::erase(&mut serde_json::Deserializer::from_str(&s)))).unwrap())
        ).unwrap_or_else(|| {panic!("Unregistered command with id {id}");}))
    }
}

impl<E: AnyError + 'static, A: AnySend + 'static, Self_: Command<Output = A, Error = E> + Send> AnyCommand for Self_ {
    fn run(mut self: Box<Self>, ctx: Context) -> Pin<Box<dyn Future<Output = Result<Box<dyn AnySend>, Box<dyn AnyError>>> + Send>> {
        Box::pin(async move {match (*self).run(ctx).await {
            Ok(a) => Ok(Box::new(a) as Box<dyn AnySend>),
            Err(e) => Err(Box::new(e) as Box<dyn AnyError>)
        }})
    }
    fn my_serialize(&self) -> Result<(u64, String), serde_json::Error> {
        println!("1");
        _Command::serialize(self)
    }
}

impl<'de> Deserialize<'de> for Box<dyn AnySend> {
    fn deserialize<D: Deserializer<'de>>(mut deserializer: D) -> Result<Self, D::Error> {
        panic!("Do NOT Deserialize Box<dyn AnySend>");
    }
}

impl<'de> Deserialize<'de> for Box<dyn AnyError> {
    fn deserialize<D: Deserializer<'de>>(mut deserializer: D) -> Result<Self, D::Error> {
        panic!("Do NOT Deserialize Box<dyn AnyError>");
    }
}

impl std::error::Error for Box<dyn AnyError> {}

impl Command for Box<dyn AnyCommand> {
    type Output = Box<dyn AnySend>;
    type Error = Box<dyn AnyError>;

    fn run(self, ctx: Context) -> impl Future<Output = Result<Self::Output, Self::Error>> {
        AnyCommand::run(self, ctx)
    }

}

pub type CommandFuture<C> = Pin<Box<dyn Future<Output = Result<<C as Command>::Output, <C as Command>::Error>> + Send>>;
pub type Requests = Vec<(Request, Vec<Endpoint>)>;
pub type Responder = oneshot::Sender<Vec<Vec<Response>>>;
pub type Callback = Sender<(Requests, Responder)>;
pub type Store = Arc<Mutex<HashMap<String, String>>>;

pub struct Context {
    callback: Callback,
    store: Store,
}


impl Context {
    fn new(callback: Callback) -> Self {
        Context {
            callback,
            store: Store::default() 
        }
    }
    fn clone(&mut self) -> Self {
        Context{
            callback: self.callback.clone(),
            store: self.store.clone()
        }
    }

    pub fn store(&mut self) -> MutexGuard<'_, HashMap<String, String>> {self.store.lock().unwrap()}

    //call many other multi-requests and air requests in parrellel

    pub async fn request<M: MultiRequest>(&mut self, mut input: M) -> Result<M::Output, M::Error> {
        todo!()
      //let (tx, rx) = tokio::sync::oneshot::channel();
      //self.tx.send(tx).await;
      //println!("GOT RESULT: {:?}", rx.await);
      //input.run(self).await
    }
}



use std::task::Waker;
use tokio::sync::mpsc;

pub struct Compiler {
    store: Store,
    purser: Purser,
    resolver: OrangeResolver,
    commands: BTreeMap<Id, Box<dyn AnyCommand>>,
    running: BTreeMap<Id, (Pin<Box<RunningCmd<Box<dyn AnyCommand>>>>, Requests, Responder)>,
}

impl Compiler {
    pub fn new() -> Self {
        Compiler {
            store: Store::default(),
            purser: Purser::new(),
            resolver: OrangeResolver,
            commands: BTreeMap::default(),
            running: BTreeMap::default()
        }
    }

    pub fn add_task(&mut self, id: Id, task: Box<dyn AnyCommand>) {
        self.commands.insert(id, task);
    }

    pub fn tick(&mut self) -> impl Future<Output = BTreeMap<Id, CommandResult>>  {
        CompilerTick(self)
    }
}

pub struct CompilerTick<'a>(&'a mut Compiler);
impl<'a> Future for CompilerTick<'a> {
    type Output = BTreeMap<Id, CommandResult>;
    fn poll(mut self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Self::Output> {
        let compiler = &mut self.0;
        let mut results = BTreeMap::default();
        let commands = std::mem::take(&mut compiler.commands);
        let store = compiler.store.clone();
        compiler.running.extend(commands.into_iter().flat_map(|(id, c)| {
            let (callback, mut rx) = mpsc::channel(1);
            let context = Context{store: store.clone(), callback};
            let mut future = pin!(RunningCmd(Some(Box::pin(c.run(context))), Some(rx)));
            match loop {
                if let Poll::Ready(result) = future.as_mut().poll(cx) {break result;}
            } {
                CommandRes::Ready(result) => {results.insert(id, CommandResult(serde_json::to_string(&result).unwrap())); None},
                CommandRes::Requesting(future, requests, responder) => Some((id, (future, requests, responder)))
            }
        }));

        let running = std::mem::take(&mut compiler.running);
        let (running, batch): (BTreeMap<_, _>, Vec<_>) = running.into_iter().map(|(id, (future, requests, responder))| {
            ((id, (future, responder)), requests) 
        }).unzip();
        let mut request = Box::pin(compiler.purser.send_batch(&mut compiler.resolver, batch.into_iter().flatten().collect()));
        let responses = loop {
            if let Poll::Ready(result) = request.as_mut().poll(cx) {break result;}
        };
        compiler.running = running.into_iter().zip(responses).flat_map(|((id, (mut future, responder)), responses)| {
            responder.send(responses).unwrap();
            match loop {
                if let Poll::Ready(result) = future.as_mut().poll(cx) {break result;}
            } {
                CommandRes::Ready(result) => {results.insert(id, CommandResult(serde_json::to_string(&result).unwrap())); None},
                CommandRes::Requesting(future, requests, responder) => Some((id, (future, requests, responder)))
            }
        }).collect();
        Poll::Ready(results)
    }
}

pub enum CommandRes<C: Command> {
    Ready(Result<C::Output, C::Error>),
    Requesting(Pin<Box<RunningCmd<C>>>, Requests, Responder)
}

pub struct RunningCmd<C: Command>(Option<CommandFuture<C>>, Option<Receiver<(Requests, Responder)>>);
impl<C: Command + Unpin> Future for RunningCmd<C> {
    type Output = CommandRes<C>;
    fn poll(mut self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Self::Output> {
        let mut future = self.0.take().unwrap();
        let mut rx = self.1.take().unwrap();
        loop {
            match future.as_mut().poll(cx) {
                Poll::Ready(r) => {break Poll::Ready(CommandRes::Ready(r));},
                Poll::Pending => {
                    if let Ok(tx) = rx.try_recv() {
                        break Poll::Ready(CommandRes::Requesting(Box::pin(RunningCmd(Some(future), Some(rx))), tx.0, tx.1));
                    }
                }
            }
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct Test2(String);
impl Command for Test2 {
    type Error = Error;
    type Output = bool;
    async fn run(self, mut ctx: Context) -> Result<Self::Output, Self::Error> {
        println!("1.1");
        Ok(false)
    }
}


pub struct RegisteredCommand(
    fn() -> u64,
    fn(&mut dyn erased_serde::Deserializer) -> Result<Box<dyn AnyCommand>, erased_serde::Error>
);
inventory::collect!(RegisteredCommand);

#[macro_export]
macro_rules! register_command {
    ($cmd:ty) => {
        inventory::submit!(RegisteredCommand(|| {
            let mut hasher = DefaultHasher::new();
            TypeId::of::<$cmd>().hash(&mut hasher);
            hasher.finish()
        }, 

        |de: &mut dyn erased_serde::Deserializer|
            Ok(Box::new(erased_serde::deserialize::<$cmd>(de)?) as Box<dyn AnyCommand>)
        ));        
    };
}

#[derive(Serialize, Deserialize)]
pub struct Test(String);
crate::register_command!(Test);
impl Command for Test {
    type Error = Error;
    type Output = bool;
    async fn run(self, mut ctx: Context) -> Result<Self::Output, Self::Error> {
        println!("started");
        ctx.store().insert("Hello".to_string(), "Goodbye".to_string());        
        println!("1");
        tokio::time::sleep(tokio::time::Duration::from_nanos(1)).await;
        //let test: (bool, bool) = ctx.request((Test2("He".to_string()), Test2("Hello".to_string()))).await?;
        //let test = Test2("Hello".to_string()).run(ctx).await?;
        println!("2");
        ctx.store().insert("Hello".to_string(), "Requested".to_string());
        println!("3");
        Ok(false)
    }
}

pub trait MultiRequest<E = ()> {
    type Error: AnyError + Serialize;
    type Output: AnySend + Serialize;

}

impl<C: Command> MultiRequest for C {
    type Error = C::Error;
    type Output = C::Output;

}

impl MultiRequest for (Request, Vec<Endpoint>) {
    type Error = Error;
    type Output = Vec<Response>;

  //fn run(self, ctx: &mut Context) -> Result<Self::Output, Self::Error> {
  //}
}

impl<E: AnyError + Serialize, M0: MultiRequest<Error = E>, M1: MultiRequest<Error = E>> MultiRequest<bool> for (M0, M1) {
    type Error = E;
    type Output = (M0::Output, M1::Output);
}

impl<M0: MultiRequest, M1: MultiRequest> MultiRequest for (M0, M1) {
    type Error = Error;
    type Output = (Result<M0::Output, M0::Error>, Result<M1::Output, M1::Error>);
}
