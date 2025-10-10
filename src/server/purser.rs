use std::collections::{BTreeMap, VecDeque};
use std::any::Any;

use super::chandler::{Request as ChandlerRequest, Response as ChandlerResponse, RawRequest};
use super::{Client, Error};

use orange_name::{self, Resolver, Signed, Name,  secp256k1::SecretKey};

pub use request_compiler::{Command, State};

#[derive(Default)]
pub struct Purser {
    client: Client,
}
impl Purser {
    pub fn new() -> Self {Purser{client: Client}}

    pub async fn send(&mut self, resolver: &mut Resolver, recipient: &Name, request: ChandlerRequest) -> Result<ChandlerResponse, Error> {
        let one_time_key = SecretKey::new();
        let payload = serde_json::to_vec(&(one_time_key.public_key(), &request)).unwrap();
        let payload = resolver.encrypt(recipient, &[], payload).await.map_err(Error::mr)?;
        let url = resolver.lookup::<String>(recipient, None, "air_url").await.map_err(Error::mr)?;
        let response = self.client.send(&url, &payload).await?;
        let payload = one_time_key.decrypt(&response).map_err(Error::mr)?;
        let signed = serde_json::from_slice::<Signed<ChandlerResponse>>(&payload).map_err(Error::mr)?;
        signed.verify(resolver, Some(recipient), None, Some(&[])).await.map_err(Error::mr)
    }

    pub async fn send_batch(&mut self, resolver: &mut Resolver, requests: Vec<Request>) -> Vec<Response> {
        let mut batches: BTreeMap<&Name, Vec<ChandlerRequest>> = BTreeMap::new();
        requests.iter().for_each(|Request(r, es)| es.iter().for_each(|e| batches.entry(e).or_default().push(r.clone())));
        let mut results: BTreeMap<Name, Result<VecDeque<ChandlerResponse>, Error>> = BTreeMap::new();
        for (recipient, batch) in batches {
            results.insert(*recipient, self.send(resolver, recipient, ChandlerRequest::batch(batch)).await.and_then(|b| b.batch().map(|b| b.into())));
        }
        requests.into_iter().map(|Request(_, es)| es.into_iter().map(|e| results.get_mut(&e).unwrap().as_mut().map(|r| r.pop_front().unwrap()).map_err(|e| e.clone())).collect()).collect()
    }
}

pub type Compiler<Output> = request_compiler::Compiler<Request, Purser, Output>;
pub type Context = request_compiler::Context<Request>;

#[derive(Debug)]
pub struct Request(pub ChandlerRequest, pub Vec<Name>);

type Response = Vec<Result<ChandlerResponse, Error>>;
impl request_compiler::Request for Request {type Response = Response;}

impl request_compiler::Handler<Request> for Purser {
    async fn handle(&mut self, store: &mut State, requests: Vec<Request>) -> Vec<Response> {
        let resolver = store.get_mut_or_default();
        self.send_batch(resolver, requests).await
    }
}

impl<I: RawRequest + Any + Send> Command<Request> for (I, Name) {
    type Output = Result<I::Response, Error>;
    async fn run(self, ctx: Context) -> Self::Output {
        (self.0, vec![self.1]).run(ctx).await.remove(0)
    }
}

impl<I: RawRequest + Any + Send> Command<Request> for (I, Vec<Name>) {
    type Output = Vec<Result<I::Response, Error>>;
    async fn run(self, mut ctx: Context) -> Self::Output {
        ctx.send(vec![Request(self.0.into(), self.1)]).await.remove(0).into_iter().map(|r| r.and_then(I::from)).collect()
    }
}
