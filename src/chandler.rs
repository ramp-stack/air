use serde::{Serialize, Deserialize};

use std::fmt::Debug;

use super::Error;

use rusqlite::Connection;

use crate::names::{Secret, Signed, secp256k1::PublicKey};
use crate::storage;

use std::net::{TcpListener, Shutdown};
use std::io::{Read, Write};
use std::time::Duration;



#[derive(Serialize, Deserialize, Debug, Clone, Hash, PartialEq, Eq)]
pub enum Request {
    Batch(Vec<Request>),
    Service(storage::Request),
}

#[derive(Serialize, Deserialize, Debug, Clone, Hash, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)]
pub enum Response {
    Batch(Vec<Response>),
    Service(storage::Response),
}
impl Response {
    pub fn storage(self) -> Result<storage::Response, Error> {
        match self {
            Response::Service(response) => Ok(response),
            e => Err(Error::mr(e))
        }
    }
    pub fn batch(self) -> Result<Vec<Response>, Error> {
        match self {
            Response::Batch(response) => Ok(response),
            e => Err(Error::mr(e))
        }
    }
}

pub struct Chandler {
    secret: Secret,
    storage: storage::Service,
    connection: Connection
}

impl Chandler {
    pub async fn start(secret: Secret) {
        let mut chandler = Chandler{secret, storage: storage::Service(true), connection: Connection::open("STORAGE.db").unwrap()};
        for mut stream in TcpListener::bind("0.0.0.0:5702").expect("Could not bind port 5702").incoming().flatten() {
            stream.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
            stream.set_write_timeout(Some(Duration::from_secs(1))).unwrap();
            let mut request = Vec::new();
            if stream.read_to_end(&mut request).is_ok() {
                let _ = stream.write_all(&chandler.handle(&request).await);
                let _ = stream.shutdown(Shutdown::Write);
            }
        }
    }

    pub async fn handle(&mut self, request: &[u8]) -> Vec<u8> {
        if let Ok(payload) = self.secret.decrypt(None, &[], request) 
        && let Ok((requester, request)) = serde_json::from_slice::<(PublicKey, Request)>(&payload) {
            let response = self.handle_request(request).await;
            let response = Signed::new(&self.secret, response).unwrap();
            return requester.encrypt(serde_json::to_vec(&response).unwrap());
        }
        Vec::new()
    }

    pub async fn handle_request(&mut self, request: Request) -> Response {
        match request {
            Request::Batch(requests) => {
                let mut responses = vec![];
                for request in requests {
                    responses.push(Box::pin(self.handle_request(request)).await);
                }
                Response::Batch(responses)
            },
            Request::Service(request) => 
                Response::Service(self.storage.process(&mut self.connection, &self.secret, request).await),
        }
    }
}
