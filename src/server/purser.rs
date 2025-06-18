use easy_secp256k1::{EasySecretKey, EasyPublicKey};
use secp256k1::SecretKey;
use serde::{Serialize, Deserialize};

use std::collections::BTreeMap;
use std::hash::Hash;
use std::fmt::Debug;

use crate::orange_name::{self, OrangeResolver, Endpoint};

use super::chandler::{Request, Response};
use super::{Client, ClientError};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Hash)]
pub enum Error {
    MaliciousResponse(String),
    ConnectionFailed(String),
    CriticalOrange(String)
}
impl std::error::Error for Error {}
impl Error {pub(crate) fn mr(e: impl Debug) -> Self {Error::MaliciousResponse(format!("{:?}", e))}}
impl From<orange_name::Error> for Error {fn from(error: orange_name::Error) -> Self {match error{
    orange_name::Error::Critical(error) => {Error::CriticalOrange(error)}
    resolution => Error::ConnectionFailed(format!("{:?}", resolution)),
}}}
impl From<ClientError> for Error {fn from(error: ClientError) -> Self {match error {
    ClientError::MaliciousResponse(response) => Error::MaliciousResponse(response),
    ClientError::ConnectionFailed(error) => Error::ConnectionFailed(error)
}}}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {write!(f, "{:?}", self)}
}

#[derive(Default)]
pub struct Purser {
    client: Client,
}
//TODO: Verify signature of endpoint on response
//TODO: Include wallet access and payment processing
impl Purser {
    pub fn new() -> Self {Purser{client: Client}}

    pub async fn send(&mut self, resolver: &mut OrangeResolver, recipient: &Endpoint, request: Request) -> Result<Response, Error> {
        let one_time_key = SecretKey::easy_new();
        let com = resolver.key(&recipient.0, Some("easy_access_com"), None).await?;
        let payload = com.easy_encrypt(serde_json::to_vec(&(one_time_key.easy_public_key(), &request)).unwrap()).unwrap();
        let response = self.client.send(recipient.1.as_str(), &payload).await?;
        serde_json::from_slice::<Response>(&one_time_key.easy_decrypt(&response).map_err(Error::mr)?).map_err(Error::mr)
    }

    pub async fn send_batches(&mut self, resolver: &mut OrangeResolver, requests: Vec<(Request, Vec<&Endpoint>)>) -> Result<Vec<Vec<Response>>, Error> {
        let mut batches: BTreeMap<&Endpoint, Vec<Request>> = BTreeMap::new();
        requests.iter().for_each(|(r, es)| es.iter().for_each(|e| batches.entry(e).or_default().push(r.clone())));
        let mut results: BTreeMap<&Endpoint, Vec<Response>> = BTreeMap::new();
        for (recipient, batch) in batches {
            results.insert(recipient, self.send(resolver, recipient, Request::batch(batch)).await?.batch()?);
        }
        Ok(requests.into_iter().rev().map(|(_, es)| es.into_iter().map(|e| results.get_mut(e).unwrap().pop().unwrap()).collect()).collect())
    }
}
