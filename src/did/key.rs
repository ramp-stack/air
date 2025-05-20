use chrono::{DateTime, Utc};
use super::{Endpoint, DidResolver, Did, Error};
use std::str::FromStr;
use easy_secp256k1::{EasySecretKey, EasyPublicKey};
use serde::{Serialize, Deserialize};
use secp256k1::{SecretKey, PublicKey};
use secp256k1::schnorr::Signature;
use url::Url;
use super::DidSecret;

const METHOD: &str = "liquid";

const ORANGE_DID: &str = "did:liquid:03190689e2ecf319d31d34af8f5bb42dcc5b88d9cc482671b076285ce3a58ae318";
//const ORANGE_URI: &str = "http://orange.me:5702";
const ORANGE_URI: &str = "localhost:5702";

#[derive(Debug)]
pub enum ResolutionError {
    UnsupportedMethod(String),
    SerdeJson(serde_json::Error),
    EasySecp256k1(easy_secp256k1::Error),
    Secp256k1(secp256k1::Error),
    Hex(hex::FromHexError),
}
impl std::error::Error for ResolutionError {}
impl std::fmt::Display for ResolutionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}
impl From<serde_json::Error> for ResolutionError {
    fn from(error: serde_json::Error) -> Self {ResolutionError::SerdeJson(error)}
}
impl From<easy_secp256k1::Error> for ResolutionError {
    fn from(error: easy_secp256k1::Error) -> Self {ResolutionError::EasySecp256k1(error)}
}
impl From<secp256k1::Error> for ResolutionError {
    fn from(error: secp256k1::Error) -> Self {ResolutionError::Secp256k1(error)}
}
impl From<hex::FromHexError> for ResolutionError {
    fn from(error: hex::FromHexError) -> Self {ResolutionError::Hex(error)}
}
impl From<ResolutionError> for Error {
    fn from(error: ResolutionError) -> Self {Error::Resolution(error.to_string())}
}

#[derive(Serialize, Deserialize, PartialOrd, PartialEq, Clone, Debug, Hash, Ord, Eq)]
pub enum LiquidSignature {
    Temporary(Signature)
}

#[derive(Serialize, Deserialize, PartialEq, Clone, Debug, Eq)]
pub enum LiquidSecret {
    Temporary(SecretKey)
}
impl LiquidSecret {
    pub fn new() -> Self {
        Self::Temporary(SecretKey::easy_new())
    }
}
impl Default for LiquidSecret {
    fn default() -> Self {Self::new()}
}

impl DidSecret for LiquidSecret {
    fn method(&self) -> &'static str {METHOD}
    fn did(&self) -> Did { 
        match self {
            Self::Temporary(key) => Did(METHOD.to_string(), key.easy_public_key().to_string())
        }
    }
    fn key(&self, _tag: &str) -> Result<SecretKey, Error> {match self {
        Self::Temporary(key) => Ok(*key)
    }}
}

#[derive(Debug)]
pub struct DidLiquid;

#[async_trait::async_trait(?Send)]
impl DidResolver for DidLiquid {
    async fn sign(&mut self, secret: Box<dyn DidSecret>, payload: &[u8]) -> Result<super::Signature, Error> {
        Ok((|| {
        let method = secret.method();
        if method != METHOD {return Err(ResolutionError::UnsupportedMethod(method.to_string()));}
        let secret: LiquidSecret = *(secret as Box<dyn std::any::Any>).downcast().unwrap();
        Ok(match secret {
            LiquidSecret::Temporary(key) => super::Signature(serde_json::to_string(&LiquidSignature::Temporary(key.easy_sign(payload))).unwrap())
        })
        })()?)
    }
    async fn verify(&mut self, did: &Did, sig: &super::Signature, payload: &[u8], _when: Option<DateTime::<Utc>>) -> Result<(), Error> {
        (|| {
            if did.0 != METHOD {return Err(ResolutionError::UnsupportedMethod(did.0.to_string()));}
            let key = PublicKey::from_slice(&hex::decode(&did.1)?)?;
            let signature: LiquidSignature = serde_json::from_str(&sig.0)?;
            match &signature {
                LiquidSignature::Temporary(sig) => Ok(key.easy_verify(sig, payload)?)
            }
        })()?;
        Ok(())
    }
    async fn keys(&mut self, did: &Did, tag: Option<&str>, _when: Option<DateTime::<Utc>>) -> Result<Vec<(String, PublicKey)>, Error> {
        Ok((|| {
            if did.0 != METHOD {return Err(ResolutionError::UnsupportedMethod(did.0.to_string()));}
            let key = PublicKey::from_slice(&hex::decode(&did.1)?)?;
            match tag {
                Some(tag) if tag != "easy_access_com" => Ok(Vec::new()),
                _ => Ok(vec![("easy_access_com".to_string(), key)]),
            }
        })()?)
    }
    async fn endpoints(&mut self, did: &Did, tag: Option<&str>, _when: Option<DateTime::<Utc>>) -> Result<Vec<(String, Endpoint)>, Error> {
        Ok((|| {
            if did.0 != METHOD {return Err(ResolutionError::UnsupportedMethod(did.0.to_string()));}
            match tag {
                Some(tag) if tag != "default" => Ok(Vec::new()),
                _ => Ok(vec![("default".to_string(), Endpoint(
                    Did::from_str(ORANGE_DID).unwrap(),
                    Url::from_str(ORANGE_URI).unwrap()
                ))]),
            }
        })()?)
    }
}
