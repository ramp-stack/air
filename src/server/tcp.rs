use std::net::{TcpListener, TcpStream, Shutdown};
use std::io::{Write, Read};
use super::{Chandler, ClientError};

pub struct Server;
impl Server {
    pub async fn start(mut chandler: Chandler){
        for mut stream in TcpListener::bind("0.0.0.0:5702").expect("Could not bind port 5702").incoming().flatten() {
            let mut request = Vec::new();
            stream.read_to_end(&mut request).unwrap();
            let _ = stream.write_all(&chandler.handle(&request).await);
            let _ = stream.shutdown(Shutdown::Write);
        }
    }
}

#[derive(Default)]
pub struct Client;
impl Client {
    pub async fn send(&mut self, url: &str, request: &[u8]) -> Result<Vec<u8>, ClientError> {
        let mut stream = TcpStream::connect(url)?;
        stream.write_all(request)?;
        stream.shutdown(Shutdown::Write)?;
        let mut response = Vec::new();
        stream.read_to_end(&mut response)?;
        Ok(response)
    }
}

impl From<std::io::Error> for ClientError {
    fn from(e: std::io::Error) -> Self {ClientError::ConnectionFailed(format!("{:?}", e))}
}
