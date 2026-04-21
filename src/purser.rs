use super::Error;

use super::storage::{Request, Response};

use std::net::{TcpStream, Shutdown};
use std::io::{Write, Read};

use crate::names::{Resolver, Name, secp256k1::SecretKey};

pub struct Purser;
impl Purser {
    fn tcp_send(url: &str, request: &[u8]) -> Result<Vec<u8>, Error> {
        let mut stream = TcpStream::connect(url)?;
        stream.write_all(request)?;
        stream.shutdown(Shutdown::Write)?;
        let mut response = Vec::new();
        stream.read_to_end(&mut response)?;
        Ok(response)
    }

    pub async fn send(resolver: &mut Resolver, recipient: &Name, request: Request) -> Result<Response, Error> {
        let one_time_key = SecretKey::new();
        let payload = serde_json::to_vec(&(one_time_key.public_key(), &request)).unwrap();
        let payload = resolver.encrypt(recipient, &[], payload).await.map_err(Error::mr)?;
        let url = resolver.url(recipient).await.map_err(Error::mr)?;
        let response = Self::tcp_send(&url, &payload)?;
        let payload = one_time_key.decrypt(&response).map_err(Error::mr)?;
        serde_json::from_slice::<Response>(&payload).map_err(Error::mr)
    }
}
