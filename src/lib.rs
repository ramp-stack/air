pub mod names;

mod storage;
pub use storage::{Request, Response};

mod chandler;
pub use chandler::Chandler;

mod purser;
pub use purser::Purser;

mod channel;
pub use channel::Channel;

pub mod contract;

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
impl From<names::Error> for Error {fn from(e: names::Error) -> Error {Error::ConnectionFailed(format!("{e:?}"))}}
impl std::error::Error for Error {}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {Error::ConnectionFailed(format!("{e:?}"))}
}
