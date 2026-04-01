use std::collections::{BTreeMap, VecDeque};

use super::chandler::{Request as ChandlerRequest, Response as ChandlerResponse};
use super::Error;

use std::net::{TcpStream, Shutdown};
use std::io::{Write, Read};

use crate::names::{Resolver, Signed, Name, secp256k1::SecretKey};

#[derive(Default)]
pub struct Purser;
impl Purser {
    async fn tcp_send(&self, url: &str, request: &[u8]) -> Result<Vec<u8>, Error> {
        let mut stream = TcpStream::connect(url)?;
        stream.write_all(request)?;
        stream.shutdown(Shutdown::Write)?;
        let mut response = Vec::new();
        stream.read_to_end(&mut response)?;
        Ok(response)
    }

    pub async fn send(&mut self, resolver: &mut Resolver, recipient: &Name, request: ChandlerRequest) -> Result<ChandlerResponse, Error> {
        let one_time_key = SecretKey::new();
        let payload = serde_json::to_vec(&(one_time_key.public_key(), &request)).unwrap();
        let payload = resolver.encrypt(recipient, &[], payload).await.map_err(Error::mr)?;
        let url = resolver.url(recipient).await.map_err(Error::mr)?;
        let response = self.tcp_send(&url, &payload).await?;
        let payload = one_time_key.decrypt(&response).map_err(Error::mr)?;
        let signed = serde_json::from_slice::<Signed<ChandlerResponse>>(&payload).map_err(Error::mr)?;
        signed.verify(resolver, Some(recipient), Some(&[])).await.map_err(Error::mr)?;
        Ok(signed.into_inner())
    }

    pub async fn send_batch(&mut self, resolver: &mut Resolver, requests: Vec<(Name, ChandlerRequest)>) -> Vec<Result<ChandlerResponse, Error>> {
        let mut batches: BTreeMap<&Name, Vec<ChandlerRequest>> = BTreeMap::new();
        requests.iter().for_each(|(e, r)| batches.entry(e).or_default().push(r.clone()));
        let mut results: BTreeMap<Name, Result<VecDeque<ChandlerResponse>, Error>> = BTreeMap::new();
        for (recipient, batch) in batches {
            results.insert(*recipient, self.send(resolver, recipient, ChandlerRequest::Batch(batch)).await.and_then(|b| b.batch().map(|b| b.into())));
        }
        requests.into_iter().map(|(e, _)| results.get_mut(&e).unwrap().as_mut().map(|r| r.pop_front().unwrap()).map_err(|e| e.clone())).collect()
    }
}

