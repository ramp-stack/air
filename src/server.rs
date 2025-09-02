#[cfg(feature = "tcp")]
mod tcp;
#[cfg(feature = "tcp")]
use tcp::Client as Client;

mod chandler;
pub use chandler::{Chandler, Service, Request, Response, ServiceRequest};

mod purser;
pub use purser::{Purser, Error, Compiler, Command, AnyCommand, CommandResult, Context};

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
        write!(f, "{self:?}")
    }
}
