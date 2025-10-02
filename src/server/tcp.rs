use std::net::{TcpListener, TcpStream, Shutdown};
use std::io::{Write, Read};
use std::time::Duration;
use super::{Chandler, Error};

pub struct Server;
impl Server {
    pub async fn start(mut chandler: Chandler){
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
}

#[derive(Default)]
pub struct Client;
impl Client {
    pub async fn send(&mut self, url: &str, request: &[u8]) -> Result<Vec<u8>, Error> {
        let mut stream = TcpStream::connect(url)?;
        stream.write_all(request)?;
        stream.shutdown(Shutdown::Write)?;
        let mut response = Vec::new();
        stream.read_to_end(&mut response)?;
        Ok(response)
    }
}
//TODO: rewrite client so that when we get a connection refused error we ping google and if google
//connects we blame the air server otherwise return a disconnected error
//
//TCP should have no ConnectionFailed error like we migh have in a tor network or more complex
//system where the client side could be at fault while still being connected to the internet
impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {Error::ConnectionFailed(format!("{e:?}"))}
}

