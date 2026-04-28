use serde::{Serialize, Deserialize};

use crate::names::{Signed, secp256k1::{Signed as KeySigned, SecretKey}, Resolver, Name, Id};
use crate::{Purser, Request, Response, Error};

use std::collections::BTreeMap;

#[derive(Serialize, Deserialize, Clone, Copy, Debug, Default)]
pub struct Channel {
    //pub servers: Vec<Name>,
    pub key: SecretKey,
    pub index: u64,
    pub timestamp: u64,
}

impl Channel {
    pub fn id(&self) -> Id {Id::hash(&self.key)}

    pub fn new(key: SecretKey, index: u64, timestamp: u64) -> Self {Channel{key, index, timestamp}}
    pub fn from(key: SecretKey) -> Self {Channel{key, index: 0, timestamp: 0}}

    pub async fn send(&mut self, outgoing: Option<&Signed<Vec<u8>>>) -> Result<Option<Option<Signed<Vec<u8>>>>, Error> {
        let key = self.key.derive(&[Id::from(self.index)]);
        let request = outgoing.as_ref().map(|signed|
            Request::Create(KeySigned::new(&key, key.public_key().encrypt(serde_json::to_vec(signed).unwrap())), true)
        ).unwrap_or(Request::Read(key.public_key(), true));
        match Purser::send(&mut Resolver, &Name::orange_me(), request).await? {
            Response::Private(m, p) => {
                self.index += 1;
                if m.as_ref().timestamp > self.timestamp {
                    self.timestamp = m.as_ref().timestamp;
                    if let Some(signed) = key.decrypt(&p).ok().and_then(|p| serde_json::from_slice::<Signed<Vec<u8>>>(&p).ok())
                    && signed.verify(&mut Resolver, None, None).await.is_ok() {
                        return Ok(Some(Some(signed)));
                    }
                }
                Ok(Some(None))
            },
            Response::Receipt(m) if m.as_ref().hash == Id::MIN => {Ok(None)},
            Response::Receipt(m) if outgoing.is_some() && m.as_ref().timestamp > self.timestamp => {
                self.index += 1;
                self.timestamp = m.as_ref().timestamp;
                Ok(None)
            }
            r => Err(Error::MaliciousResponse(format!("{r:?}"))),
        }
    }

    pub async fn send_all(&mut self, mut outgoing: Option<Signed<Vec<u8>>>) -> Result<BTreeMap<u64, Signed<Vec<u8>>>, Error> {
        let mut results = BTreeMap::new();
        loop {
            match self.send(outgoing.as_ref()).await? {
                None => {
                    if let Some(outgoing) = outgoing.take() {
                        results.insert(self.timestamp, outgoing); 
                    }
                    break Ok(results)
                },
                Some(m) => {if let Some(m) = m {results.insert(self.timestamp, m);}}
            }
        }
    }
}

//Fire and confirm but forget
//Send and get timestamp back
//
//Send at an index and confirm data matches and get timestamp back

#[cfg(test)]
mod test {
    use super::*;

    use crate::names::Secret;

     #[tokio::test]
    async fn test_channel() {
        let secret = Secret::new();

        let key = SecretKey::new();

        let mut channel = Channel::from(key);
        let mut channel_b = Channel::from(key);

        let msg = Signed::new(&secret, b"hello".to_vec()).unwrap();
        let msg_b = Signed::new(&secret, b"goodbye".to_vec()).unwrap();
        assert_eq!(channel.send(Some(&msg)).await, Ok(None));//Channel sent message successfuly
        assert_eq!(channel_b.send(Some(&msg_b)).await, Ok(Some(Some(msg))));//Channel read instead of sending
        assert_eq!(channel_b.send(Some(&msg_b)).await, Ok(None));//Channel sent message successfuly
        assert_eq!(channel.send(None).await, Ok(Some(Some(msg_b))));//Channel read message successfuly
    }
}

