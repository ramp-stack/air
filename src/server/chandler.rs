use easy_secp256k1::{EasySecretKey, EasyPublicKey};
use secp256k1::{SecretKey, PublicKey};
use serde::{Serialize, Deserialize};

use std::fmt::Debug;

use crate::did::DidResolver;
use super::Handler;

#[async_trait::async_trait(?Send)]
pub trait Service: Send {
    fn name(&self) -> String;
    fn catalog(&self) -> String;
    async fn process(&mut self, resolver: &mut dyn DidResolver, request: String) -> String;
}

#[derive(Serialize, Deserialize, Debug, Clone, Hash, PartialEq, Eq)]
pub enum Request {
    Batch(Vec<Box<Request>>),
    Service(String, String),
    //Catalog,
}

#[derive(Serialize, Deserialize, Debug, Clone, Hash)]
pub enum Response {
    Batch(Vec<Box<Response>>),
    OutOfService(String),
    //Catalog(BTreeMap<String, String>),
    Ok(String)
}

pub struct Chandler {
    dir: SecretKey,
    resolver: Box<dyn DidResolver + Send>,
    services: Vec<Box<dyn Service>>
}

impl Chandler {
    pub fn new(dir: SecretKey, resolver: Box<dyn DidResolver + Send>) -> Self {
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
                Some(service) => Response::Ok(service.process(&mut *self.resolver, payload).await),
                None => Response::OutOfService(name)
            },
            //Request::Catalog => Response::Catalog(self.services.iter().map(|s| (s.name(), s.catalog())).collect()),
        }
    }
}

#[async_trait::async_trait(?Send)]
impl Handler for Chandler {
    //TODO: Add Payment System and Request Batches
    //Vec<Vec<Request>> Each Vec<Request> is a batch that must be executed in order(Payment failure to
    //one stops the batch)
    async fn handle(&mut self, request: &[u8]) -> Vec<u8> {
        if let Ok(payload) = self.dir.easy_decrypt(request) {
            if let Ok((requester, request)) = serde_json::from_slice::<(PublicKey, Request)>(&payload) {
                let response = self.handle_request(request).await;
                return requester.easy_encrypt(serde_json::to_vec(&response).unwrap()).unwrap();
            }
        }
        return Vec::new();
    }
}
