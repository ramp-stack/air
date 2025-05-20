use std::net::{TcpListener, TcpStream, Shutdown};
use std::io::{Write, Read};
use super::{Handler, ClientError};

pub struct Server;
impl Server {
    pub async fn start(mut handler: impl Handler){
        for mut stream in TcpListener::bind("localhost:5702").expect("Could not bind port 5702").incoming().flatten() {
            let mut request = Vec::new();
            stream.read_to_end(&mut request).unwrap();
            stream.write_all(&handler.handle(&request).await).unwrap();
            stream.shutdown(Shutdown::Write).unwrap();
        }
    }
}

pub struct Client;
#[async_trait::async_trait(?Send)]
impl super::Client for Client {
    async fn send(&mut self, url: &str, request: &[u8]) -> Result<Vec<u8>, ClientError> {
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
