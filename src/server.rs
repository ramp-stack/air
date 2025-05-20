#[cfg(feature = "tcp")]
mod tcp;
#[cfg(feature = "tcp")]
pub use tcp::Client as TcpClient;

mod chandler;
pub use chandler::{Chandler, Service, Request as ChandlerRequest, Response as ChandlerResponse};

mod purser;
pub use purser::{Purser, Request, DefaultPurser, Error, ServiceRequest, BatchRequest, AnyRequest, AnyResponse};

#[derive(Debug)]
pub enum ClientError {
    ///This error is caused by a malicious response from the server
    MaliciousResponse(String),
    ///Caused by some local circumstances that need to be corrected
    ConnectionFailed(String)
}
impl std::error::Error for ClientError {}
impl std::fmt::Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[async_trait::async_trait(?Send)]
pub trait Client {
    async fn send(&mut self, url: &str, request: &[u8]) -> Result<Vec<u8>, ClientError>;
}

#[async_trait::async_trait(?Send)]
pub trait Handler {
    async fn handle(&mut self, request: &[u8]) -> Vec<u8>;
}
