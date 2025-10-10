#[cfg(feature = "tcp")]
mod tcp;
#[cfg(feature = "tcp")]
use tcp::Client as Client;

mod chandler;
pub use chandler::{Chandler, Service, Request, Response, ServiceRequest, RawRequest};

pub mod purser;
pub use purser::{Purser, Compiler, Command, Context, Request as PurserRequest};
pub use crate::map_request_enum;


#[derive(Debug, Clone, PartialEq)]
pub enum Error {
    ///This error is caused by a malicious or no response from the server
    MaliciousResponse(String),
    ///Caused by the client for some reason such as not being configured properly
    ConnectionFailed(String),
    ///We are disconnected from the internet
    Disconnected
}
impl Error {
    pub(crate) fn mr(e: impl std::fmt::Debug) -> Self {Error::MaliciousResponse(format!("{e:?}"))}
}
impl std::error::Error for Error {}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
