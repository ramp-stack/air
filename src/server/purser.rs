use easy_secp256k1::{EasySecretKey, EasyPublicKey};
use secp256k1::SecretKey;
use serde::{Serialize, Deserialize};

use std::collections::{VecDeque, BTreeMap, HashMap};
use std::hash::Hash;
use std::fmt::Debug;
use std::task::Poll;
use std::pin::Pin;
use std::any::TypeId;
use tokio::sync::mpsc;
use crate::orange_name::{self, OrangeResolver, Endpoint};
use crate::Id;

use super::chandler::{Request, Response, ServiceRequest};
use super::{Client, ClientError};

use std::sync::{Arc, Mutex};
use tokio::sync::{Mutex as TokioMutex, MutexGuard as TokioMutexGuard};
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

#[derive(Default)]
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
        serde_json::from_slice::<Result<Response, String>>(&one_time_key.easy_decrypt(&response).map_err(Error::mr)?).map_err(Error::mr)?.map_err(Error::mr)
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

pub trait AnySend: std::any::Any + Send {}
impl<A: std::any::Any + Send> AnySend for A {}

pub trait AnyError: AnySend + std::error::Error {}
impl<E: AnySend + std::error::Error> AnyError for E {}
impl std::error::Error for Box<dyn AnyError> {}

trait CastAnySend {fn cast<T: 'static>(self) -> T;}
impl CastAnySend for Box<dyn AnySend> {fn cast<T: 'static>(self) -> T {
    *(self as Box<dyn std::any::Any>).downcast().unwrap()
}}

trait AnyRequest<Output> {fn any(self) -> Box<dyn MultiRequest<Box<dyn AnySend>>>;}
impl<Output: Send + 'static, M: MultiRequest<Output> + 'static> AnyRequest<Output> for M {
    fn any(self) -> Box<dyn MultiRequest<Box<dyn AnySend>>> {
        Box::new(Box::new(self) as Box<dyn MultiRequest<Output>>)
    }
}

pub struct CommandResult(Box<dyn AnySend>);
impl CommandResult {
    pub fn cast<A: AnySend>(self) -> Option<A> {
        (self.0 as Box<dyn std::any::Any>).downcast::<A>().ok().map(|t| *t)
    }
}

pub trait Command: AnySend {
    type Output: AnySend + where Self: Sized;
    fn run(self, ctx: Context) -> impl Future<Output = Self::Output> + Send where Self: Sized;
}

pub trait AnyCommand: Send {
    fn run(self: Box<Self>, ctx: Context) -> PBFut<Box<dyn AnySend>>; 
}

impl<A: AnySend + 'static, Self_: Command<Output = A> + Send> AnyCommand for Self_ {
    fn run(self: Box<Self>, ctx: Context) -> PBFut<Box<dyn AnySend>> {
        Box::pin(async move {Box::new((*self).run(ctx).await) as Box<dyn AnySend>})
    }
}

impl Command for Box<dyn AnyCommand> {
    type Output = Box<dyn AnySend>;

    fn run(self, ctx: Context) -> impl Future<Output = Self::Output> {
        AnyCommand::run(self, ctx)
    }
}

#[derive(Default)]
pub struct State(HashMap<TypeId, Box<dyn std::any::Any + Send>>);
impl State {
    pub fn set<A: AnySend>(&mut self, set: A) {
        self.0.insert(TypeId::of::<A>(), Box::new(set));
    }

    pub fn get<A: AnySend>(&self) -> &A {
        self.0.get(&TypeId::of::<A>()).unwrap().downcast_ref().unwrap()
    }

    pub fn try_get<A: AnySend>(&self) -> Option<&A> {
        self.0.get(&TypeId::of::<A>()).map(|a| *a.downcast_ref().unwrap())
    }

    pub fn try_get_mut<A: AnySend>(&mut self) -> Option<&mut A> {
        self.0.get_mut(&TypeId::of::<A>()).map(|a| a.downcast_mut().unwrap())
    }

    pub fn get_mut_or_default<A: AnySend + Default>(&mut self) -> &mut A {
        self.0.entry(TypeId::of::<A>()).or_insert_with(|| Box::new(A::default())).downcast_mut().unwrap()
    }
}


type Handler<'a> = Box<dyn FnOnce(Vec<(Request, Vec<Endpoint>)>) -> Pin<Box<dyn Future<Output = Result<Vec<Vec<Response>>, Error>> + Send + 'a>> + Send + 'a>;
type Commands<Output> = Arc<Mutex<BTreeMap<Id, Box<dyn MultiRequest<Output>>>>>;
type InProgress<Output> = Arc<Mutex<BTreeMap<Id, (Pin<Box<Running<Output>>>, Requests, Responder)>>>;
type Requests = Vec<(Request, Vec<Endpoint>)>;
type Responder = oneshot::Sender<Result<Vec<Vec<Response>>, Error>>;
type Callback = Sender<(Requests, Responder)>;
type Store = Arc<TokioMutex<State>>;
type PBFut<Output> = Pin<Box<dyn Future<Output = Output> + Send>>;

#[derive(Clone)]
pub struct Context {
    callback: Callback,
    store: Store,
}

impl Context {
    async fn send(&mut self, requests: Vec<(Request, Vec<Endpoint>)>) -> Result<Vec<Vec<Response>>, Error> {
        let (tx, rx) = oneshot::channel();
        self.callback.send((requests, tx)).await.unwrap();
        rx.await.unwrap()
    }

    pub async fn store(&mut self) -> TokioMutexGuard<'_, State> {
        self.store.lock().await
    }

    pub async fn try_get_mut<A: AnySend>(&mut self) -> Option<tokio::sync::MappedMutexGuard<'_, A>> {
        let mut guard = self.store.lock().await;
        if guard.try_get_mut::<A>().is_some() {
            Some(TokioMutexGuard::map(guard, |store| store.try_get_mut().unwrap()))
        } else {None}
    }

    pub async fn get_mut_or_default<A: AnySend + Default>(&mut self) -> tokio::sync::MappedMutexGuard<'_, A> {
        TokioMutexGuard::map(self.store.lock().await, |store| store.get_mut_or_default())
    }

    pub async fn run<Output: Send, M: MultiRequest<Output>>(&mut self, input: M) -> Output {
        Box::new(input).run(self.clone()).await
    }
}

#[derive(Default)]
pub struct Compiler {
    purser: Purser,
    commands: Commands<Box<dyn AnySend>>,
    running: InProgress<Box<dyn AnySend>>,
    store: Store,
}

impl Compiler {
    pub fn new() -> Self {
        Compiler{
            purser: Purser::new(),
            commands: Commands::default(),
            running: InProgress::default(),
            store: Store::default(),
        }
    }

    pub async fn store(&mut self) -> TokioMutexGuard<'_, State> {
        self.store.lock().await
    }

    pub async fn tick(&mut self) -> BTreeMap<Id, CommandResult> {
        let store = self.store.clone();
        CompilerTick::<Box<dyn AnySend>>::new(
            self.commands.clone(), self.running.clone(), self.store.clone(),
            Box::new(|requests: Requests| {
                Box::pin(async {
                    let mut store = store.lock().await;
                    let resolver = store.get_mut_or_default();
                    self.purser.send_batch(resolver, requests).await
                })
            })
        ).run().await.into_iter().map(|(id, r)| (id, CommandResult(r))).collect()
    }

    pub fn is_empty(&self) -> bool {
        self.commands.lock().unwrap().is_empty() && self.running.lock().unwrap().is_empty()
    }

    pub fn add_task(&mut self, id: Id, task: impl Command) {
        self.commands.lock().unwrap().insert(id, Box::new(Box::new(task) as Box<dyn AnyCommand>));
    }
}

pub struct CompilerTick<'a, Output>{
    commands: Commands<Output>,
    running: InProgress<Output>,
    store: Store,
    handler: Option<Handler<'a>>,
}
impl<'a, Output: Send + 'static> CompilerTick<'a, Output> {
    pub fn new(
        commands: Commands<Output>,
        running: InProgress<Output>,
        store: Store,
        handler: Handler<'a> 
    ) -> Self {
        CompilerTick{commands, running, store, handler: Some(handler)}
    }

    pub async fn run(mut self) -> BTreeMap<Id, Output> {
        let mut results = BTreeMap::default();
        let commands = std::mem::take(&mut *self.commands.lock().unwrap());
        let store = self.store.clone();
        for (id, c) in commands {
            match Running::new(c, &store).await {
                RunningResult::Ready(result) => {results.insert(id, result);},
                RunningResult::Requesting(future, requests, responder) => {self.running.lock().unwrap().insert(id, (future, requests, responder));}
            }
        }
        let running = std::mem::take(&mut *self.running.lock().unwrap());
        let (running, batch): (BTreeMap<_, _>, Vec<_>) = running.into_iter().map(
            |(id, (future, requests, responder))| ((id, (future, responder)), requests) 
        ).unzip();
        let counts: Vec<_> = batch.iter().map(|b| b.len()).collect();
        let mut responses: Result<VecDeque<Vec<Response>>, Error> = (self.handler.take().unwrap())(batch.into_iter().flatten().collect()).await.map(|r| r.into());
        for ((id, (future, responder)), count) in running.into_iter().zip(counts) {
            responder.send(match &mut responses {
                Ok(responses) => {
                    let mut r = Vec::new();
                    for _ in 0..count {
                        r.push(responses.pop_front().unwrap());
                    }
                    Ok(r)
                },
                Err(e) => Err(e.clone())
            }).unwrap();
            match future.await {
                RunningResult::Ready(result) => {results.insert(id, result);},
                RunningResult::Requesting(future, requests, responder) => {self.running.lock().unwrap().insert(id, (future, requests, responder));}
            }
        }
        results
    }
}
pub enum RunningResult<Output> {
    Ready(Output),
    Requesting(Pin<Box<Running<Output>>>, Requests, Responder)
}

pub struct Running<Output>(Option<PBFut<Output>>, Option<Receiver<(Requests, Responder)>>);
impl<Output: Send + 'static> Running<Output> {
    pub fn new(m: Box<dyn MultiRequest<Output>>, store: &Store) -> Self {
        let (callback, rx) = mpsc::channel(1);
        let context = Context{store: store.clone(), callback};
        Running(Some(Box::pin(m.run(context))), Some(rx))
    }
}

impl<Output: 'static> Future for Running<Output> {
    type Output = RunningResult<Output>;
    fn poll(mut self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Self::Output> {
        match self.0.as_mut().unwrap().as_mut().poll(cx) {
            Poll::Ready(r) => Poll::Ready(RunningResult::Ready(r)),
            Poll::Pending => {
                if let Ok(tx) = self.1.as_mut().unwrap().try_recv() {
                    Poll::Ready(RunningResult::Requesting(Box::pin(Running(self.0.take(), self.1.take())), tx.0, tx.1))
                } else {Poll::Pending}
            }
        }
    }
}

pub struct RunMany<Output> {
    order: Vec<Id>,
    commands: Commands<Output>,
    running: InProgress<Output>,
    context: Context,
}
impl<Output: Send + 'static> RunMany<Output> {
    pub fn new(commands: Vec<Box<dyn MultiRequest<Output>>>, context: Context) -> Self {
        let (order, commands) = commands.into_iter().map(|c| {let id = Id::random(); (id, (id, c))}).unzip();
        RunMany{
            order,
            commands: Arc::new(Mutex::new(commands)),
            running: InProgress::default(),
            context,
        }
    }

    fn is_empty(&self) -> bool {
        self.commands.lock().unwrap().is_empty() && self.running.lock().unwrap().is_empty()
    }

    fn tick(&mut self) -> CompilerTick<'static, Output> {
        let c = self.context.clone();
        CompilerTick::<Output>::new(self.commands.clone(), self.running.clone(), self.context.store.clone(), 
            Box::new(|req: Requests| {
                Box::pin(Box::new(req).run(c))
            })
        )
    }

    async fn run(mut self) -> Vec<Output> {
        let mut results = BTreeMap::new();
        while !self.is_empty() {
            results.extend(self.tick().run().await);
        }
        self.order.into_iter().map(|i| results.remove(&i).unwrap()).collect()
    }
}

pub trait MultiRequest<Output: Send>: Send {
    fn run(self: Box<Self>, ctx: Context) -> PBFut<Output>;
}

impl<C: Command> MultiRequest<Vec<C::Output>> for Vec<C> {
    fn run(self: Box<Self>, ctx: Context) -> PBFut<Vec<C::Output>> {
        Box::pin(RunMany::new(self.into_iter().map(|c| Box::new(c) as Box<dyn MultiRequest<C::Output>>).collect(), ctx).run())
    }
}

impl<C: Command> MultiRequest<C::Output> for C {
    fn run(self: Box<Self>, ctx: Context) -> PBFut<C::Output> {
        Box::pin(Command::run(*self, ctx))
    }
}

impl<Output: AnySend> MultiRequest<Box<dyn AnySend>> for Box<dyn MultiRequest<Output>> {
    fn run(self: Box<Self>, ctx: Context) -> PBFut<Box<dyn AnySend>> {
        Box::pin(async move {
            Box::new((*self).run(ctx).await) as Box<dyn AnySend>
        })
    }
}

impl<I: ServiceRequest + AnySend> MultiRequest<Result<I::Response, Error>> for (I, Endpoint) {
    fn run(self: Box<Self>, mut ctx: Context) -> PBFut<Result<I::Response, Error>> {
        Box::pin(async move {
            ctx.send(vec![(self.0.into(), vec![self.1])]).await.and_then(|mut r| r.remove(0).remove(0).service::<I>())
        })
    }
}

impl<I: ServiceRequest + AnySend> MultiRequest<Result<Vec<I::Response>, Error>> for (I, Vec<Endpoint>) {
    fn run(self: Box<Self>, mut ctx: Context) -> PBFut<Result<Vec<I::Response>, Error>> {
        Box::pin(async move {
            ctx.send(vec![(self.0.into(), self.1)]).await.and_then(|mut r| r.remove(0).into_iter().map(|r| r.service::<I>()).collect())
        })
    }
}

impl<I: ServiceRequest + AnySend> MultiRequest<Result<Vec<Vec<I::Response>>, Error>> for Vec<(I, Vec<Endpoint>)> {
    fn run(self: Box<Self>, mut ctx: Context) -> PBFut<Result<Vec<Vec<I::Response>>, Error>> {
        Box::pin(async move {
            ctx.send(self.into_iter().map(|(r, e)| (r.into(), e)).collect()).await.and_then(|r| r.into_iter().map(|r| r.into_iter().map(|r| r.service::<I>()).collect()).collect())
        })
    }
}

macro_rules! impl_result_tuple {
    (
        ($t_head:ident, $( $t:ident ),+);
        ($tt_head:ident, $($tt:ident),+);
        ($i_head:tt, $( $i:tt ),+)
    ) => {
        impl<
            E: AnyError,
            $t_head: AnySend, $( $t: AnySend ),+,
            $tt_head: MultiRequest<Result<$t_head, E>> + 'static, $( $tt: MultiRequest<Result<$t, E>> + 'static ),+
        > MultiRequest<Result<($t_head, $( $t ),+), E>> for ($tt_head, $( $tt ),+) {
            fn run(self: Box<Self>, ctx: Context) -> PBFut<Result<($t_head, $( $t ),+), E>> {
                Box::pin(async move {
                    let mut results = RunMany::new(vec![
                        $( self.$i.any() ),+, self.$i_head.any()
                    ], ctx).run().await;
                    Ok((
                        results.remove(0).cast::<Result<$t_head, E>>()?,
                        $( {results.remove(0).cast::<Result<$t, E>>()?} ),+
                    ))
                })
            }
        }
        impl_result_tuple!(($($t),+); ($($tt),+); ($($i),+));
    };

    (
        ($t:ident);
        ($tt:ident);
        ($i:tt)
    ) => {}
}
impl_result_tuple!((T0, T1, T2, T3, T4, T5, T6, T7); (M0, M1, M2, M3, M4, M5, M6, M7); (7, 6, 5, 4, 3, 2, 1, 0));

macro_rules! impl_tuple {
    (
        ($t_head:ident, $( $t:ident ),+);
        ($tt_head:ident, $($tt:ident),+);
        ($i_head:tt, $( $i:tt ),+)
    ) => {
        impl<
            $t_head: AnySend, $( $t: AnySend ),+,
            $tt_head: MultiRequest<$t_head> + 'static, $( $tt: MultiRequest<$t> + 'static ),+
        > MultiRequest<($t_head, $( $t ),+)> for ($tt_head, $( $tt ),+) {
            fn run(self: Box<Self>, ctx: Context) -> PBFut<($t_head, $( $t ),+)> {
                Box::pin(async move {
                    let mut results = RunMany::new(vec![
                        $( self.$i.any() ),+, self.$i_head.any()
                    ], ctx).run().await;
                    (
                        results.remove(0).cast::<$t_head>(),
                        $( results.remove(0).cast::<$t>() ),+
                    )
                })
            }
        }
        impl_tuple!(($($t),+); ($($tt),+); ($($i),+));
    };

    (
        ($t:ident);
        ($tt:ident);
        ($i:tt)
    ) => {}
}

impl_tuple!((T0, T1, T2, T3, T4, T5, T6, T7); (M0, M1, M2, M3, M4, M5, M6, M7); (7, 6, 5, 4, 3, 2, 1, 0));
