use serde::{Serialize, Deserialize};

use std::pin::Pin;
use std::fmt::Debug;

use super::Error;

use orange_name::{Resolver, Secret, Signed, secp256k1::PublicKey, Id};

pub trait Service: Send {
    const NAME: &str;
    type Request: ServiceRequest + Serialize + for<'a> Deserialize<'a>;
    //fn name(&self) -> String;
    fn catalog(&self) -> String;
    fn process(&mut self, resolver: &mut Resolver, secret: &Secret, request: Self::Request) -> impl Future<Output = <Self::Request as ServiceRequest>::Response>;
}

pub trait ServiceRequest: Serialize + for<'a> Deserialize<'a> {
    type Response: Serialize + for<'a> Deserialize<'a> + Send;
    type Service: Service;
}

pub trait RawRequest {
    type Response: Send;
    fn into(self) -> Request;
    fn from(response: Response) -> Result<Self::Response, Error>;
}

impl<R: ServiceRequest> RawRequest for R {
    type Response = R::Response;
    fn into(self) -> Request {Request::service(self)}
    fn from(response: Response) -> Result<Self::Response, Error> {response.service::<R>()}
}

impl RawRequest for Request {
    type Response = Response;
    fn into(self) -> Request {self}
    fn from(response: Response) -> Result<Self::Response, Error> {Ok(response)}
}

trait ErasedService {
    fn name(&self) -> String;
    //fn catalog(&self) -> String;
    fn process<'a>(&'a mut self, resolver: &'a mut Resolver, secret: &'a Secret, request: String) -> Pin<Box<dyn Future<Output = Result<String, String>> + 'a>>;
}

impl<R: ServiceRequest, Self_: Service<Request = R> + Send> ErasedService for Self_ {
    fn name(&self) -> String {Self_::NAME.to_string()}
    //fn catalog(&self) -> String {Service::catalog(self)}
    fn process<'a>(&'a mut self, resolver: &'a mut Resolver, secret: &'a Secret, request: String) -> Pin<Box<dyn Future<Output = Result<String, String>> + 'a>> {
        Box::pin(async move {
            Ok(serde_json::to_string(&Service::process(self, resolver, secret, serde_json::from_str(&request).map_err(|e| format!("Could not parse request: {e}"))?).await).unwrap())
        })
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Hash, PartialEq, Eq)]
pub enum Request {
    Batch(Vec<Box<Request>>),
    Service(String, String),
    //Catalog,
}

impl Request {
    pub fn service<S: ServiceRequest>(request: S) -> Self {
        Request::Service(S::Service::NAME.to_string(), serde_json::to_string(&request).unwrap())
    }
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
    pub fn service<S: ServiceRequest>(self) -> Result<S::Response, Error> {
        match self {
            Response::Service(response) => response.and_then(|r|
                serde_json::from_str::<S::Response>(&r).map_err(|e| e.to_string())
            ).map_err(Error::mr),
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
    dir: Secret,
    resolver: Resolver,
    services: Vec<(Secret, Box<dyn ErasedService>)>
}

impl Chandler {
    pub fn new(dir: Secret, resolver: Resolver) -> Self {
        Chandler{dir, resolver, services: Vec::new()}
    }
    pub fn add_service<S: Service + 'static>(&mut self, service: S) {
        self.services.push((self.dir.derive(&[Id::hash(&S::NAME.to_string())]).unwrap(), Box::new(service)));
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
            Request::Service(name, payload) => match self.services.iter_mut().find(|(_, s)| s.name() == name) {
                Some((secret, service)) => Response::Service(service.process(&mut self.resolver, secret, payload).await),
                None => Response::OutOfService(name)
            },
            //Request::Catalog => Response::Catalog(self.services.iter().map(|s| (s.name(), s.catalog())).collect()),
        }
    }

    //TODO: Add Payment System
    pub async fn handle(&mut self, request: &[u8]) -> Vec<u8> {
        if let Ok(payload) = self.dir.decrypt(&crate::now(), &[], request) 
        && let Ok((requester, request)) = serde_json::from_slice::<(PublicKey, Request)>(&payload) {
            let response = self.handle_request(request).await;
            let response = Signed::new(&self.dir, &[], response).unwrap();
            return requester.encrypt(serde_json::to_vec(&response).unwrap()).unwrap();
        }
        Vec::new()
    }
}

#[macro_export]
macro_rules! map_request_enum {
    ($e:ident::$a:ident: $i:ty => $r:ident: $o:ty) => {
        #[derive(Serialize, Deserialize, Debug)]
        pub struct $a($i);
        impl RawRequest for $a {
            type Response = $o;
            fn into(self) -> $crate::server::Request {$crate::server::Request::service($e::$a(self.0))}
            fn from(response: $crate::server::Response) -> Result<Self::Response, Error> {match response.service::<$e>()? {
                $r::$a(d) => Ok(d),
                r => Err(Error::mr(r))
            }}
        }
    }
}


