use serde::{Serialize, Deserialize};
use secp256k1::PublicKey;

use std::collections::BTreeMap;
use std::hash::Hash;
use std::fmt::Debug;

use crate::did::{self, DidResolver, Signature, Did};
use crate::server::Error;

mod service;
pub use service::{StorageService, Request, Response};

pub mod requests;

pub mod records;

//pub mod protocol;

//pub mod orange;

//pub mod agent;

const NAME: &str = "STORAGE";

#[derive(Serialize, Deserialize, Clone, Debug, Hash, PartialEq, Eq)]
pub struct PrivateItem {
    pub discover: PublicKey,
    pub delete: Option<PublicKey>,
    pub payload: Vec<u8>
}

#[derive(Serialize, Deserialize, Clone, Debug, Hash)]
pub enum Actor {
    Key(PublicKey),
    Did(Did)
}
impl std::fmt::Display for Actor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", match self { 
            Self::Key(i) => i.to_string(),
            Self::Did(i) => i.to_string()
        })
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, Hash)]
pub struct DMItem(Actor, Vec<u8>);

pub struct ReadDMResult(Vec<(Did, Signature, Vec<u8>)>);
impl ReadDMResult {
    pub async fn process(self, resolver: &mut dyn DidResolver) -> Result<Vec<(Did, Vec<u8>)>, Error> {
        let mut results = Vec::new();
        for item in self.0 {
            match resolver.verify(&item.0, &item.1, &item.2, None).await {
                Err(did::Error::Critical(e)) => {return Err(did::Error::Critical(e).into());},
                Err(_) => {},
                Ok(()) => {results.push((item.0, item.2));}
            }
        }
        Ok(results)
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, Hash)]
pub struct PublicItem {
    pub uuid: String,
    pub payload: Vec<u8>,
    pub tags: BTreeMap<String, String>
}
