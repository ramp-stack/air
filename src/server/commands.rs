use std::collections::{VecDeque, BTreeMap};
use std::task::Poll;
use std::pin::Pin;
use std::fmt::Debug;

use orange_name::Id;

use anyanymap::Map;
use std::sync::{Arc, Mutex};

use tokio::sync::mpsc;
use tokio::sync::{Mutex as TokioMutex, MutexGuard as TokioMutexGuard};
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::sync::oneshot;

use std::any::Any;

pub trait Request: Send + 'static {
    type Response: Send + Debug;
}

pub trait Command<R: Request>: Any + Send {
    type Output: Any + Send + where Self: Sized;
    fn run(self, ctx: Context<R>) -> impl Future<Output = Self::Output> + Send where Self: Sized;

    fn map<O: Send + 'static, M: Command<R, Output = O> + Send + 'static>(
        self, map: impl FnOnce(Self::Output) -> M + Send + 'static
    ) -> Mapped<R, Self::Output, O> where Self: Sized {
        Mapped::new(self, map)
    }
}

pub trait Handler<R: Request>: Send {
    fn handle(&mut self, store: &mut State, requests: Vec<R>) -> impl Future<Output = Vec<R::Response>> + Send;
}

pub trait AnyCommand<R: Request>: Send {fn run(self: Box<Self>, ctx: Context<R>) -> PBFut<Box<dyn Any + Send>>; }
impl<R: Request, A: Any + Send + 'static, Self_: Command<R, Output = A> + Send> AnyCommand<R> for Self_ {
    fn run(self: Box<Self>, ctx: Context<R>) -> PBFut<Box<dyn Any + Send>> {
        Box::pin(async move {Box::new((*self).run(ctx).await) as Box<dyn Any + Send>})
    }
}
impl<R: Request> Command<R> for Box<dyn AnyCommand<R>> {
    type Output = Box<dyn Any + Send>;
    fn run(self, ctx: Context<R>) -> impl Future<Output = Self::Output> {AnyCommand::run(self, ctx)}
}

pub struct Mapped<R, I: Send, O: Send>(
    Box<dyn _Command<R, I>>, Box<dyn FnOnce(I) -> Box<dyn _Command<R,  O> + Send + 'static> + Send + 'static>
);
impl<R: Request, I: Send + 'static, O: Send + 'static> Mapped<R, I, O> {
    pub fn new<CI: Command<R, Output = I>, CO: Command<R, Output = O> + Send + 'static>(
        input: CI,
        map: impl FnOnce(I) -> CO + Send + 'static
    ) -> Self {Mapped(Box::new(input), Box::new(|i: I| Box::new(map(i)) as Box<dyn _Command<R, O> + Send + 'static>))}
}
impl<R: Request, I: Send + 'static, O: Send + 'static> Command<R> for Mapped<R, I, O> {
    type Output = O;
    async fn run(self, ctx: Context<R>) -> Self::Output {
        (self.1)(self.0.run_m(ctx.clone()).await).run_m(ctx).await
    }
}

Map!(State: std::any::Any, Send);

pub struct Context<R: Request> {
    callback: Callback<R>,
    store: Store,
}
impl<R: Request> Clone for Context<R> {
    fn clone(&self) -> Self {Context{callback: self.callback.clone(), store: self.store.clone()}}
}
    
impl<R: Request> Context<R> {
    pub async fn send(&mut self, requests: Vec<R>) -> Vec<R::Response> {
        let (tx, rx) = oneshot::channel();
        self.callback.send((requests, tx)).await.unwrap();
        rx.await.unwrap()
    }

    pub async fn store(&mut self) -> TokioMutexGuard<'_, State> {
        self.store.lock().await
    }

    pub async fn get_mut<A: Any + Send>(&mut self) -> Option<tokio::sync::MappedMutexGuard<'_, A>> {
        let mut guard = self.store.lock().await;
        if guard.get_mut::<A>().is_some() {
            Some(TokioMutexGuard::map(guard, |store| store.get_mut().unwrap()))
        } else {None}
    }

    pub async fn get_mut_or_default<A: Any + Send + Default>(&mut self) -> tokio::sync::MappedMutexGuard<'_, A> {
        TokioMutexGuard::map(self.store.lock().await, |store| store.get_mut_or_default())
    }

    pub async fn run<Output: Send + 'static, M: Command<R, Output = Output>>(&mut self, input: M) -> Output {
        Box::new(input).run_m(self.clone()).await
    }
}

impl<R: Request> Handler<R> for Context<R> {
    async fn handle(&mut self, _store: &mut State, requests: Vec<R>) -> Vec<R::Response> {self.send(requests).await}
}

pub struct Compiler<R: Request, H: Handler<R>, Output> {
    commands: Commands<R, Output>,
    running: InProgress<R, Output>,
    store: Store,
    handler: H
}
impl<R: Request, H: Handler<R>, Output: Send + 'static> Compiler<R, H, Output> {
    pub fn new(
        handler: H
    ) -> Self {
        Compiler{
            commands: Commands::default(),
            running: InProgress::default(),
            store: Store::default(),
            handler
        }
    }

    pub async fn store(&mut self) -> TokioMutexGuard<'_, State> {
        self.store.lock().await
    }

    pub fn add_task(&mut self, id: Id, command: impl Command<R, Output = Output>) {
        self.commands.lock().unwrap().insert(id, Box::new(command));
    }

    pub fn is_empty(&self) -> bool {
        self.commands.lock().unwrap().is_empty() && self.running.lock().unwrap().is_empty()
    }

    pub async fn tick(&mut self) -> BTreeMap<Id, Output> {
        CompilerTick::<R, Output>::new(self.commands.clone(), self.running.clone(), self.store.clone(), 
            Box::new(|req: Vec<R>| {
                Box::pin(async move {
                    let mut state = self.store.lock().await;
                    self.handler.handle(&mut state, req).await
                })
            })
        ).run().await
    }

    pub async fn run(mut self) -> BTreeMap<Id, Output> {
        let mut results = BTreeMap::new();
        while !self.is_empty() {
            results.extend(self.tick().await);
        }
        results
    }

    async fn run_in_order(
        commands: Vec<Box<dyn _Command<R, Output>>>,
        store: Store,
        handler: H
    ) -> Vec<Output> {
        let (order, commands): (Vec<Id>, _) = commands.into_iter().map(|c| {let id = Id::random(); (id, (id, c))}).unzip();
        let mut results = Compiler{
            commands: Arc::new(Mutex::new(commands)),
            running: InProgress::default(),
            store,
            handler
        }.run().await;
        order.into_iter().map(|i| results.remove(&i).unwrap()).collect()
    }


}

type HandlerOnce<'a, R> = Box<dyn FnOnce(Vec<R>) -> Pin<Box<dyn Future<Output = Vec<<R as Request>::Response>> + Send + 'a>> + Send + 'a>;
type Commands<R, Output> = Arc<Mutex<BTreeMap<Id, Box<dyn _Command<R, Output>>>>>;
type InProgress<R, Output> = Arc<Mutex<BTreeMap<Id, (Pin<Box<Running<R, Output>>>, Vec<R>, Responder<R>)>>>;
type Responder<R> = oneshot::Sender<Vec<<R as Request>::Response>>;
type Callback<R> = Sender<(Vec<R>, Responder<R>)>;
type Store = Arc<TokioMutex<State>>;
type PBFut<Output> = Pin<Box<dyn Future<Output = Output> + Send>>;

struct CompilerTick<'a, R: Request, Output>{
    commands: Commands<R, Output>,
    running: InProgress<R, Output>,
    store: Store,
    handler: HandlerOnce<'a, R>,
}
impl<'a, R: Request, Output: Send + 'static> CompilerTick<'a, R, Output> {
    pub fn new(
        commands: Commands<R, Output>,
        running: InProgress<R, Output>,
        store: Store,
        handler: HandlerOnce<'a, R> 
    ) -> Self {
        CompilerTick{commands, running, store, handler}
    }

    pub async fn run(self) -> BTreeMap<Id, Output> {
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
        let mut responses: VecDeque<R::Response> = (self.handler)(
            batch.into_iter().flatten().collect()
        ).await.into();
        for ((id, (future, responder)), count) in running.into_iter().zip(counts) {
            responder.send({
                let mut r = Vec::new();
                for _ in 0..count {
                    r.push(responses.pop_front().unwrap());
                }
                r
            }).unwrap();
            match future.await {
                RunningResult::Ready(result) => {results.insert(id, result);},
                RunningResult::Requesting(future, requests, responder) => {self.running.lock().unwrap().insert(id, (future, requests, responder));}
            }
        }
        results
    }
}
enum RunningResult<R: Request, Output> {
    Ready(Output),
    Requesting(Pin<Box<Running<R, Output>>>, Vec<R>, Responder<R>)
}

struct Running<R: Request, Output>(Option<PBFut<Output>>, Option<Receiver<(Vec<R>, Responder<R>)>>);
impl<R: Request, Output: Send + 'static> Running<R, Output> {
    pub fn new(m: Box<dyn _Command<R, Output>>, store: &Store) -> Self {
        let (callback, rx) = mpsc::channel(1);
        let context = Context{store: store.clone(), callback};
        Running(Some(Box::pin(m.run_m(context))), Some(rx))
    }
}

impl<R: Request, Output: 'static> Future for Running<R, Output> {
    type Output = RunningResult<R, Output>;
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



trait _Command<R: Request, Output: Send + 'static>: Send {
    fn run_m(self: Box<Self>, ctx: Context<R>) -> PBFut<Output>;
}

impl<R: Request, C: Command<R>> Command<R> for Vec<C> {
    type Output = Vec<C::Output>;
    async fn run(self, ctx: Context<R>) -> Self::Output {
        Compiler::run_in_order(
            self.into_iter().map(|c| Box::new(c) as Box<dyn _Command<R, C::Output>>).collect(),
            ctx.store.clone(),
            ctx,
        ).await
    }
}

impl<R: Request, C: Command<R>> _Command<R, C::Output> for C {
    fn run_m(self: Box<Self>, ctx: Context<R>) -> PBFut<C::Output> {
        Box::pin(Command::run(*self, ctx))
    }
}

impl<R: Request, Output: Any + Send> Command<R> for Box<dyn _Command<R, Output>> {
    type Output = Box<dyn Any + Send>;
    async fn run(self, ctx: Context<R>) -> Self::Output {
        Box::new(self.run_m(ctx).await) as Box<dyn Any + Send>
    }
}

trait AnyRequest<R: Request, Output> {fn any(self) -> Box<dyn _Command<R, Box<dyn Any + Send>>>;}
impl<R: Request, Output: Send + 'static, M: _Command<R, Output> + 'static> AnyRequest<R, Output> for M {
    fn any(self) -> Box<dyn _Command<R, Box<dyn Any + Send>>> {
        Box::new(Box::new(self) as Box<dyn _Command<R, Output>>)
    }
}

macro_rules! impl_result_tuple {
    (
        ($t_head:ident, $( $t:ident ),+);
        ($tt_head:ident, $($tt:ident),+);
        ($i_head:tt, $( $i:tt ),+)
    ) => {
        impl<
            R: Request,
            $t_head: Any + Send, $( $t: Any + Send ),+,
            $tt_head: Command<R, Output = $t_head> + 'static, $( $tt: Command<R, Output = $t> + 'static ),+
        > Command<R> for ($tt_head, $( $tt ),+) {
            type Output = ($t_head, $( $t ),+);
            async fn run(self, ctx: Context<R>) -> ($t_head, $( $t ),+) {
                let mut results = Compiler::run_in_order(vec![
                    $( self.$i.any() ),+, self.$i_head.any()
                ], ctx.store.clone(), ctx).await;
                (
                    *results.remove(0).downcast::<$t_head>().unwrap(),
                    $( {*results.remove(0).downcast::<$t>().unwrap()} ),+
                )
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
