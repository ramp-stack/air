use rusqlite::Connection;

use crate::names::{Secret, secp256k1::PublicKey};
use crate::storage::{Service, Request};

use std::net::{TcpListener, Shutdown};
use std::io::{Read, Write};
use std::time::Duration;

pub struct Chandler {
    secret: Secret,
    storage: Service,
    connection: Connection
}

impl Chandler {
    pub async fn start(secret: Secret) {
        let mut chandler = Chandler{secret, storage: Service(true), connection: Connection::open("STORAGE.db").unwrap()};
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
            let response = self.storage.process(&mut self.connection, &self.secret, request).await;
            return requester.encrypt(serde_json::to_vec(&response).unwrap());
        }
        Vec::new()
    }
}
