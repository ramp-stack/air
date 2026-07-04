use std::any::TypeId;
use std::collections::BTreeMap;
use std::pin::Pin;

use crate::{Secret, Context, Id};

pub trait Service: Send + 'static {
    fn id() -> Id;
    fn new(ctx: &mut Context, secret: Secret) -> impl Future<Output = Self> + Send;
    fn run(&mut self, ctx: &mut Context) -> impl Future<Output = ()> + Send;
    fn shutdown(self, ctx: &mut Context) -> impl Future<Output = ()> + Send;
}

type ErasedService = Box<dyn FnOnce(Context, Secret) -> Pin<Box<dyn Future<Output = ()> + Send>> + Send>;
#[derive(Default)]
pub struct Services(BTreeMap<TypeId, (Id, ErasedService)>);
impl Services {
    #[allow(clippy::should_implement_trait)]
    pub fn add<S: Service>(mut self) -> Self {
        self.0.insert(TypeId::of::<S>(), (S::id(), Box::new(move |mut ctx: Context, secret: Secret| Box::pin(async move { 
            let token = ctx.1.token.clone();
            tokio::select! {
                mut service = S::new(&mut ctx, secret) => loop {tokio::select! {
                    biased;
                    _ = token.cancelled() => {
                        service.shutdown(&mut ctx).await;
                        break;
                    }
                    _ = service.run(&mut ctx) => {}
                }},
                _ = token.cancelled() => {}
            }
        }))));
        self
    }

    pub(crate) fn start(self, context: Context) {
        context.1.handle.clone().spawn(async move {
            let s_key = context.1.secret.derive(&[Id::hash("SERVICES")]);
            for (_, (service_id, service)) in self.0 {
                context.1.spawn(service(context.clone(), s_key.derive(&[service_id])));
            }
        });
    }
}

use crate::{Metadata, Reactant, Contract, Reactants, Instance, names::now};
use serde::{Serialize, Deserialize};
use tokio::time::{sleep, Sleep, Duration};

pub const LOCK: u64 = 20_000_000_000;//20 seconds
pub const MARGIN: u64 = 10_000_000_000;//10 seconds

pub struct Lock<S>(S, Instance<ServiceLock>, Id, Secret, Option<Pin<Box<Sleep>>>);
impl<S: Service> Lock<S> {
    async fn obtain(instance: &mut Instance<ServiceLock>, my_id: Id, remaining: &mut Option<Pin<Box<Sleep>>>) -> bool {
        let mut clear = false;
        if remaining.as_ref().map(|r| r.is_elapsed()).unwrap_or(true) {loop {
            println!("applying obtain");
            match instance.try_apply(Obtain(my_id)).confirmed().await {
                Ok(time) => {
                    *remaining = Some(Box::pin(sleep(Duration::from_nanos((time+LOCK).saturating_sub(now()+MARGIN)))));
                    break
                },
                Err(wait) => {
                    clear = true;
                    println!("waiting to unlock: {:?}", wait);
                    loop {tokio::select!{
                        _ = sleep(Duration::from_nanos(wait)) => {break},
                        output = instance.listen_confirmed() => {
                            if output.downcast::<Release>().map(|r| r.is_ok()).unwrap_or_default() {break}
                        }
                    }}
                }
            }
        }}
        clear
    }
}
impl<S: Service> Service for Lock<S> {
    fn id() -> Id {Id::hash(&format!("Lock<{}>", S::id()))}
    async fn new(ctx: &mut Context, secret: Secret) -> Self {
        let my_id = Id::random();
        let mut lock = ctx.create(S::id());
        let mut remaining = None;
        println!("obtaining lock");
        let _ = Self::obtain(&mut lock, my_id, &mut remaining).await;
        println!("obtained lock");
        let service = S::new(ctx, secret.clone()).await;
        Lock(service, lock, my_id, secret, remaining)
    }
  
    async fn run(&mut self, ctx: &mut Context) {
        let mut fut = Box::pin(self.0.run(ctx));
        loop {
            if tokio::select! {
                _ = &mut fut => {break},
                _ = self.4.as_mut().unwrap() => {true},
                output = self.1.listen_confirmed() => {
                    output.downcast::<Release>().map(|r| r.is_ok()).unwrap_or_default()
                }
            } && Self::obtain(&mut self.1, self.2, &mut self.4).await {
                drop(fut);
                self.0 = S::new(ctx, self.3.clone()).await;
                fut = Box::pin(self.0.run(ctx));
            }
        }
    }

    async fn shutdown(mut self, ctx: &mut Context) {
        if self.4.map(|r| !r.is_elapsed()).unwrap_or_default() {
            self.0.shutdown(ctx).await;
        }
        let _ = self.1.apply(Release(self.2)).confirmed().await;
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
struct ServiceLock(Id, u64);
impl Contract for ServiceLock {
    type Init = Id;
    fn id() -> Id {Id::hash("ServiceLock")}

    fn init(_init: Self::Init, _metadata: Metadata) -> Self {ServiceLock::default()}

    fn reactants() -> Reactants<Self> {Reactants::default().add::<Obtain>().add::<Release>()}
}

#[derive(Serialize, Deserialize, Clone, Debug)]
struct Obtain(Id);
impl Reactant<ServiceLock> for Obtain {
    fn id() -> Id {Id::hash("Obtain")}
    type Output = Result<u64, u64>;
    fn apply(self, lock: &mut ServiceLock, metadata: Metadata) -> Self::Output {
        match lock {
            ServiceLock(id, time) if *id == self.0 || *time+LOCK < metadata.timestamp => {
                *time = metadata.timestamp;
                *id = self.0;
                Ok(*time)
            },
            ServiceLock(_, time) => {
                Err(*time+LOCK - metadata.timestamp)
            }
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
struct Release(Id);
impl Reactant<ServiceLock> for Release {
    fn id() -> Id {Id::hash("Release")}
    type Output = Result<Id, Id>;
    fn apply(self, lock: &mut ServiceLock, _metadata: Metadata) -> Self::Output {
        if lock.0 == self.0 {
            lock.1 = 0;
            Ok(lock.0)
        } else {Err(lock.0)}
    }
}
