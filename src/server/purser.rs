use easy_secp256k1::{EasySecretKey, EasyPublicKey};
use secp256k1::SecretKey;
use serde::{Serialize, Deserialize};

use std::collections::VecDeque;
use std::ops::{DerefMut, Deref};
use std::hash::{Hasher, Hash};
use std::fmt::Debug;
use std::any::Any;

use crate::did::{self, DidResolver, Endpoint};

use super::chandler::{Request as ChandlerRequest, Response as ChandlerResponse};
use super::{Client, ClientError};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Hash)]
pub enum Error {
    MaliciousResponse(String),
    ConnectionFailed(String),
}

impl Error {
    fn mr(e: impl Debug) -> Self {Error::MaliciousResponse(format!("{:?}", e))}
}
impl From<did::Error> for Error {
    fn from(error: did::Error) -> Self {match error{
        did::Error::Resolution(error) => Error::ConnectionFailed(format!("Did Resolution: {:?}", error)),
        did::Error::Critical(error) => {panic!("Critical Did Error: {:?}", error);}
    }}
}
impl From<ClientError> for Error {
    fn from(error: ClientError) -> Self {
        match error {
            ClientError::MaliciousResponse(response) => Error::MaliciousResponse(response),
            ClientError::ConnectionFailed(error) => Error::ConnectionFailed(error)
        }
    }
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {write!(f, "{:?}", self)}
}

pub trait Request: AsRef<ChandlerRequest> {
    type Output;
    fn process(self, response: Result<ChandlerResponse, Error>) -> Self::Output;
}

#[async_trait::async_trait(?Send)]
pub trait Purser {
    async fn send_raw(&mut self, recipient: &Endpoint, request: &ChandlerRequest) -> Result<ChandlerResponse, Error>;
    async fn send<T, R: Request<Output = T>>(&mut self, recipient: &Endpoint, request: R) -> T where Self: Sized;
}

pub struct DefaultPurser {
    client: Box<dyn Client>,
    resolver: Box<dyn DidResolver>
}
//TODO: Include wallet access and payment processing
impl DefaultPurser {
    pub fn new(client: impl Client + 'static, resolver: impl DidResolver + 'static) -> Self {
        DefaultPurser{client: Box::new(client), resolver: Box::new(resolver)}
    }
}

#[async_trait::async_trait(?Send)]
impl Purser for DefaultPurser {
    async fn send_raw(&mut self, recipient: &Endpoint, request: &ChandlerRequest) -> Result<ChandlerResponse, Error> {
        let one_time_key = SecretKey::easy_new();
        let com = self.resolver.key(&recipient.0, Some("easy_access_com"), None).await?;
        let payload = com.easy_encrypt(serde_json::to_vec(&(one_time_key.easy_public_key(), request)).unwrap()).unwrap();
        let response = self.client.send(recipient.1.as_str(), &payload).await?;
        serde_json::from_slice::<ChandlerResponse>(&one_time_key.easy_decrypt(&response).map_err(Error::mr)?).map_err(Error::mr)
    }
    async fn send<T, R: Request<Output = T>>(&mut self, recipient: &Endpoint, request: R) -> T {
        let response = self.send_raw(recipient, request.as_ref()).await;
        request.process(response)
    }
}


#[derive(Serialize, Deserialize, Clone, Debug, Hash)]
pub struct BatchResponse(VecDeque<ChandlerResponse>);
impl Deref for BatchResponse {
    type Target = VecDeque<ChandlerResponse>;
    fn deref(&self) -> &Self::Target {&self.0}
}
impl DerefMut for BatchResponse {
    fn deref_mut(&mut self) -> &mut Self::Target {&mut self.0}
}
impl BatchResponse {
    pub fn process_next<T, R: Request<Output = T>>(&mut self, request: R) -> Option<T> {
        self.0.pop_front().map(|i| request.process(Ok(i)))
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, Hash)]
pub struct BatchRequest(ChandlerRequest);
impl AsRef<ChandlerRequest> for BatchRequest {fn as_ref(&self) -> &ChandlerRequest {&self.0}}
impl Default for BatchRequest {fn default() -> Self {Self::new()}}
impl BatchRequest {
    pub fn new() -> Self {Self(ChandlerRequest::Batch(vec![]))}
    pub fn push(&mut self, request: &impl AsRef<ChandlerRequest>) {
        if let ChandlerRequest::Batch(batch) = &mut self.0 {
            batch.push(Box::new(request.as_ref().clone()));
        }
    }
}
impl<R: AsRef<ChandlerRequest>, const N: usize> From<[&R; N]> for BatchRequest {
    fn from(arr: [&R; N]) -> Self {Self::from_iter(arr)}
}
impl<'a, R: AsRef<ChandlerRequest>> FromIterator<&'a R> for BatchRequest {
    fn from_iter<T: IntoIterator<Item = &'a R>>(iter: T) -> Self {
        let mut batch = BatchRequest::new(); batch.extend(iter); batch 
    }
}
impl<'a, R: AsRef<ChandlerRequest>> Extend<&'a R> for BatchRequest {
    fn extend<T: IntoIterator<Item = &'a R>>(&mut self, iter: T) {
        if let ChandlerRequest::Batch(batch) = &mut self.0 {
            batch.extend(iter.into_iter().map(|r| Box::new(r.as_ref().clone())))
        }
    }
}
impl Request for BatchRequest {
    type Output = Result<BatchResponse, Error>;
    fn process(self, response: Result<ChandlerResponse, Error>) -> Self::Output {
        match response? {
            ChandlerResponse::Batch(responses) => {
                Ok(BatchResponse(responses.into_iter().map(|c| *c).collect()))
            },
            _ => Err(Error::mr(self))
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, Hash)]
pub struct ServiceRequest(ChandlerRequest);
impl AsRef<ChandlerRequest> for ServiceRequest {fn as_ref(&self) -> &ChandlerRequest {&self.0}}
impl ServiceRequest {
    pub fn new(name: &str, request: &impl Serialize) -> Result<Self, serde_json::Error> {
        Ok(ServiceRequest(ChandlerRequest::Service(name.to_string(), serde_json::to_string(&request)?)))
    }
}
impl Request for ServiceRequest {
    type Output = Result<String, Error>;
    fn process(self, response: Result<ChandlerResponse, Error>) -> Self::Output {
        match response? {
            ChandlerResponse::Ok(response) => Ok(response),
            _ => Err(Error::mr(self))
        }
    }
}

pub struct AnyResponse(Box<dyn Any>);
impl AnyResponse{
    pub fn from_request<R: Request<Output = T>, T: 'static>(self) -> Option<T> {
        (self.0 as Box<dyn Any>).downcast().ok().map(|r| *r)
    }
}

type Callback = Box<dyn FnOnce(ChandlerResponse) -> Box<dyn Any>>;
pub struct AnyRequest(ChandlerRequest, String, Option<Callback>);
impl AsRef<ChandlerRequest> for AnyRequest {fn as_ref(&self) -> &ChandlerRequest {&self.0}}
impl AnyRequest {
    pub fn new<T: Any>(request: impl Request<Output = T> + Debug + Hash + 'static) -> Self {
        AnyRequest(
            request.as_ref().clone(), format!("{:?}", request),
            Some(Box::new(move |response: ChandlerResponse| Box::new(request.process(Ok(response))))),
        )
    }
}
impl Request for AnyRequest {
    type Output = Result<AnyResponse, Error>;
    fn process(self, response: Result<ChandlerResponse, Error>) -> Self::Output {
        Ok(AnyResponse(self.2.expect("Already Sent")(response?)))
    }
}

impl Debug for AnyRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.1)
    }
}

impl Hash for AnyRequest {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.hash(state)
    }
}

impl PartialEq for AnyRequest {
    fn eq(&self, other: &Self) -> bool {self.0 == other.0}
}
impl Eq for AnyRequest {}
