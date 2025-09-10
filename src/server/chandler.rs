use easy_secp256k1::{EasySecretKey, EasyPublicKey};
use secp256k1::{SecretKey, PublicKey};
use serde::{Serialize, Deserialize};

use std::pin::Pin;
use std::fmt::Debug;

use super::Error;

use orange_name::OrangeResolver;

pub trait Service: Send {
    type Request: ServiceRequest;
    fn name(&self) -> String;
    fn catalog(&self) -> String;
    fn process(&mut self, resolver: &mut OrangeResolver, request: Self::Request) -> impl Future<Output = <Self::Request as ServiceRequest>::Response>;
}

pub trait ServiceRequest: Into<Request> + Serialize + for<'a> Deserialize<'a> {
    type Response: Serialize + for<'a> Deserialize<'a> + Send;

    fn from_chandler(response: Response) -> Result<Self::Response, Error> {
        response.service::<Self>()
    }
}

trait ErasedService {
    fn name(&self) -> String;
    //fn catalog(&self) -> String;
    fn process<'a>(&'a mut self, resolver: &'a mut OrangeResolver, request: String) -> Pin<Box<dyn Future<Output = Result<String, String>> + 'a>>;
}

impl<R: ServiceRequest, Self_: Service<Request = R> + Send> ErasedService for Self_ {
    fn name(&self) -> String {Service::name(self)}
    //fn catalog(&self) -> String {Service::catalog(self)}
    fn process<'a>(&'a mut self, resolver: &'a mut OrangeResolver, request: String) -> Pin<Box<dyn Future<Output = Result<String, String>> + 'a>> {
        Box::pin(async move {
            Ok(serde_json::to_string(&Service::process(self, resolver, serde_json::from_str(&request).map_err(|e| format!("Could not parse request: {e}"))?).await).unwrap())
        })
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Hash, PartialEq, Eq)]
pub enum Request {
    Batch(Vec<Box<Request>>),
    Service(String, String),
    //Catalog,
}
impl ServiceRequest for Request {
    type Response = Response;
}
impl Request {
    pub fn batch(requests: Vec<Request>) -> Request {
        Request::Batch(requests.into_iter().map(Box::new).collect())
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Hash, PartialEq, Eq)]
pub enum Response {
    Batch(Vec<Box<Response>>),
    OutOfService(String),
    Service(Result<String, String>),
    //Catalog(BTreeMap<String, String>),
}
impl Response {
    pub fn service<R: ServiceRequest>(&self) -> Result<R::Response, Error> {
        match self {
            Response::Service(response) => serde_json::from_str(response.as_ref().map_err(Error::mr)?).map_err(Error::mr),
            e => Err(Error::mr(e))
        }
    }

    pub fn batch(self) -> Result<Vec<Response>, Error> {
        match self {
            Response::Batch(response) => Ok(response.into_iter().map(|r| *r).collect()),
            e => Err(Error::mr(e))
        }
    }
}

pub struct Chandler {
    dir: SecretKey,
    resolver: OrangeResolver,
    services: Vec<Box<dyn ErasedService>>
}

impl Chandler {
    pub fn new(dir: SecretKey, resolver: OrangeResolver) -> Self {
        Chandler{dir, resolver, services: Vec::new()}
    }
    pub fn add_service(&mut self, service: impl Service + 'static) {
        self.services.push(Box::new(service));
    }

    pub async fn start(self) {
        #[cfg(feature = "tcp")]
        super::tcp::Server::start(self).await
    }

    pub async fn handle_request(&mut self, request: Request) -> Response {
        match request {
            Request::Batch(requests) => {
                let mut responses = vec![];
                for request in requests {
                    responses.push(Box::new(Box::pin(self.handle_request(*request)).await));
                }
                Response::Batch(responses)
            },
            Request::Service(name, payload) => match self.services.iter_mut().find(|s| s.name() == name) {
                Some(service) => Response::Service(service.process(&mut self.resolver, payload).await),
                None => Response::OutOfService(name)
            },
            //Request::Catalog => Response::Catalog(self.services.iter().map(|s| (s.name(), s.catalog())).collect()),
        }
    }

    //TODO: Sign Responses for Clientside verification
    //TODO: Add Payment System and Request Batches
    //Vec<Vec<Request>> Each Vec<Request> is a batch that must be executed in order(Payment failure to
    //one stops the batch)
    pub async fn handle(&mut self, request: &[u8]) -> Vec<u8> {
        if let Ok(payload) = self.dir.easy_decrypt(request) 
        && let Ok((requester, request)) = serde_json::from_slice::<(PublicKey, Request)>(&payload) {
            let response = self.handle_request(request).await;
            return requester.easy_encrypt(serde_json::to_vec(&response).unwrap()).unwrap();
        }
        Vec::new()
    }
}
