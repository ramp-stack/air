use easy_secp256k1::{EasySecretKey, EasyPublicKey};
use secp256k1::{SecretKey, PublicKey};
use serde::{Serialize, Deserialize};

use std::fmt::Debug;

use crate::orange_name::OrangeResolver;
use super::Error;

#[async_trait::async_trait(?Send)]
pub trait Service: Send {
    fn name(&self) -> String;
    fn catalog(&self) -> String;
    async fn process(&mut self, resolver: &mut OrangeResolver, request: String) -> String;
}

#[derive(Serialize, Deserialize, Debug, Clone, Hash, PartialEq, Eq)]
pub enum Request {
    Batch(Vec<Box<Request>>),
    Service(String, String),
    //Catalog,
}
impl Request {
    pub fn batch(requests: Vec<Request>) -> Request {
        Request::Batch(requests.into_iter().map(Box::new).collect())
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Hash)]
pub enum Response {
    Batch(Vec<Box<Response>>),
    OutOfService(String),
    Service(String),
    //Catalog(BTreeMap<String, String>),
}
impl Response {
    pub fn service<T: for<'a> Deserialize<'a>>(&self) -> Result<T, Error> {
        match self {
            Response::Service(response) => serde_json::from_str(response).map_err(Error::mr),
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
    services: Vec<Box<dyn Service>>
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
        if let Ok(payload) = self.dir.easy_decrypt(request) {
            if let Ok((requester, request)) = serde_json::from_slice::<(PublicKey, Request)>(&payload) {
                let response = self.handle_request(request).await;
                return requester.easy_encrypt(serde_json::to_vec(&response).unwrap()).unwrap();
            }
        }
        Vec::new()
    }
}
