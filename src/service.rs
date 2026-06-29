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
            let mut service = S::new(&mut ctx, secret).await;
            let token = ctx.air.token.clone();
            loop {
                tokio::select! {
                    biased;
                    _ = token.cancelled() => {
                        service.shutdown(&mut ctx).await;
                        break;
                    }
                    _ = service.run(&mut ctx) => {}
                }
            }
        }))));
        self
    }

    pub(crate) fn start(self, context: Context) {
        context.air.handle.clone().spawn(async move {
            let s_key = context.air.secret.derive(&[Id::hash("SERVICES")]);
            for (_, (service_id, service)) in self.0 {
                context.air.spawn(service(context.clone(), s_key.derive(&[service_id])));
            }
        });
    }
}

use crate::{Metadata, Reactant, Contract, Reactants, Instance, names::now};
use serde::{Serialize, Deserialize};
use tokio::time::{sleep, Duration};

pub const LOCK: u64 = 20_000_000_000;//20 seconds
pub const MARGIN: u64 = 10_000_000_000;//10 seconds

pub struct Lock<S>(Option<S>, Instance<ServiceLock>, Id, Secret);
impl<S: Service> Lock<S> {
    async fn remaining(instance: &mut Instance<ServiceLock>, my_id: Id) -> u64 {
        let current = instance.wait_for_initialized().await;
        let remaining = (current.1+LOCK).saturating_sub(now()+MARGIN);
        if current.0 == my_id {remaining} else {0}
    }

    async fn obtain(instance: &mut Instance<ServiceLock>, my_id: Id) -> (u64, bool) {
        let mut clear = false;
        let remaining = Self::remaining(instance, my_id).await;
        println!("Obtaining");
        if remaining > 0 {
            println!("Still Hav: {:?}: {}", remaining / 1_000_000, my_id);
            (remaining, clear)
        } else { loop {
            match instance.try_apply(Obtain(my_id)).await {
                Ok(time) => {
                    let remaining = (time+LOCK).saturating_sub(now()+MARGIN);
                    println!("Obtained: {:?}: {}", remaining / 1_000_000, my_id);
                    break (remaining, clear);
                },
                Err(wait) => {
                    println!("I don't have or lost the lock");
                    clear = true;
                    let sleep = sleep(Duration::from_nanos(wait));
                    tokio::select!{
                        _ = sleep => {},
                        Ok(_) = instance.listen_confirmed::<Release>() => {}
                    }
                }
            }
        }}
    }
}
impl<S: Service> Service for Lock<S> {
    fn id() -> Id {Id::hash(&format!("Lock<{}>", S::id()))}
    async fn new(ctx: &mut Context, secret: Secret) -> Self {
        Lock(None, ctx.create(S::id()), Id::random(), secret)
    }
  
    async fn run(&mut self, ctx: &mut Context) {
        println!("Running");
        let (mut remaining, _) = Self::obtain(&mut self.1, self.2).await;
        if self.0.is_none() {self.0 = Some(S::new(ctx, self.3.clone()).await);}
        let mut fut = Some(Box::pin(self.0.as_mut().unwrap().run(ctx)));
        println!("Running as {}: with: {remaining}", self.2);
        loop { tokio::select! {
            _ = fut.as_mut().unwrap() => break,
            _ = sleep(Duration::from_nanos(remaining)) => {
                println!("Renewing Lock During Run");
                let (r, c) = Self::obtain(&mut self.1, self.2).await;
                remaining = r;
                if c {
                    drop(fut);
                    self.0 = Some(S::new(ctx, self.3.clone()).await);
                    fut = Some(Box::pin(self.0.as_mut().unwrap().run(ctx)));
                }
            }
            Ok(_) = self.1.listen_confirmed::<Release>() => {
                println!("Try Obtaining lock after release");
                let (r, c) = Self::obtain(&mut self.1, self.2).await;
                remaining = r;
                if c {
                    drop(fut);
                    self.0 = Some(S::new(ctx, self.3.clone()).await);
                    fut = Some(Box::pin(self.0.as_mut().unwrap().run(ctx)));
                }
            }
        }}
    }

    async fn shutdown(mut self, ctx: &mut Context) {
        let remaining = Self::remaining(&mut self.1, self.2).await;
        println!("shutdown_info: {:?}: {}", remaining / 1_000_000, self.2);
        if remaining > 0 {
            self.0.unwrap().shutdown(ctx).await;
        }
        let _ = self.1.apply(Release(self.2)).await;
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
    type Result = Result<u64, u64>;
    fn apply(self, lock: &mut ServiceLock, metadata: Metadata) -> Self::Result {
        match lock {
            ServiceLock(id, time) if *id == self.0 || *time+LOCK < metadata.timestamp => {
                *time = metadata.timestamp;
                *id = self.0;
                Ok(*time)
            },
            ServiceLock(_, time) => Err(*time+LOCK - metadata.timestamp)
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
struct Release(Id);
impl Reactant<ServiceLock> for Release {
    fn id() -> Id {Id::hash("Release")}
    type Result = Result<Id, Id>;
    fn apply(self, lock: &mut ServiceLock, _metadata: Metadata) -> Self::Result {
        if lock.0 == self.0 {
            lock.1 = 0;
            Ok(lock.0)
        } else {Err(lock.0)}
    }
}
