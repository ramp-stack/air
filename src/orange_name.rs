use easy_secp256k1::{EasySecretKey, EasyPublicKey, EasyHash, Hashable};
use secp256k1::{SecretKey, PublicKey};
use secp256k1::schnorr::Signature;
use std::str::FromStr;
use std::hash::Hash;
use std::fmt::Debug;

use serde::{Serialize, Deserialize};
use url::Url;
use crate::DateTime;

const ORANGEME_NAME: &str = "orange_name:03190689e2ecf319d31d34af8f5bb42dcc5b88d9cc482671b076285ce3a58ae318";
//const ORANGEME_URI: &str = "tcp://air.orange.me:5702";
const ORANGEME_URI: &str = "localhost:5702";


#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug, Hash)]
pub enum Error {
    ///Error occured in a critical and unexpected manner inside the did resolver and the program
    ///relying on this resolver should exit and report the error
    Critical(String),
    ///Error occured if the resolver was unable to resolve the did or verify the signature
    Resolution(String),
}
impl Error {
    pub fn is_critical(&self) -> bool {matches!(self, Error::Critical(_))}
}
impl From<ResolutionError> for Error {fn from(error: ResolutionError) -> Self {Error::Resolution(error.to_string())}}
impl std::error::Error for Error {}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}
#[derive(Debug)]
pub enum ResolutionError {
    UnsupportedMethod(String),
    SerdeJson(serde_json::Error),
    EasySecp256k1(easy_secp256k1::Error),
    Secp256k1(secp256k1::Error),
    Hex(hex::FromHexError),
}
impl std::error::Error for ResolutionError {}
impl std::fmt::Display for ResolutionError {fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {write!(f, "{:?}", self)}}
impl From<serde_json::Error> for ResolutionError {fn from(error: serde_json::Error) -> Self {ResolutionError::SerdeJson(error)}}
impl From<easy_secp256k1::Error> for ResolutionError {fn from(error: easy_secp256k1::Error) -> Self {ResolutionError::EasySecp256k1(error)}}
impl From<secp256k1::Error> for ResolutionError {fn from(error: secp256k1::Error) -> Self {ResolutionError::Secp256k1(error)}}
impl From<hex::FromHexError> for ResolutionError {fn from(error: hex::FromHexError) -> Self {ResolutionError::Hex(error)}}

#[derive(Clone, Debug, Hash, Ord, Eq, PartialOrd, PartialEq)]
#[derive(serde_with::SerializeDisplay)]
#[derive(serde_with::DeserializeFromStr)]
pub struct OrangeName(PublicKey);
impl std::fmt::Display for OrangeName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "orange_name:{}", self.0)
    }
}
impl std::str::FromStr for OrangeName {
    type Err = secp256k1::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let split = s.split(":").collect::<Vec<_>>();
        if split.len() != 2 || split[0] != "orange_name" {return Err(secp256k1::Error::InvalidPublicKey);}
        Ok(OrangeName(PublicKey::from_str(split[1])?))
    }
}

#[derive(Serialize, Deserialize, PartialOrd, PartialEq, Clone, Debug, Hash, Ord, Eq)]
pub enum OrangeSignature {
    Temporary(Signature)
}

#[derive(Serialize, Deserialize, PartialEq, Clone, Debug, Eq)]
pub enum OrangeSecret {
    Temporary(SecretKey)
}
impl OrangeSecret {
    pub fn new() -> Self {Self::Temporary(SecretKey::easy_new())}
    pub fn name(&self) -> OrangeName { 
        match self {
            Self::Temporary(key) => OrangeName(key.easy_public_key())
        }
    }
    fn key(&self) -> SecretKey {match self {Self::Temporary(key) => *key}}
}
impl Default for OrangeSecret {fn default() -> Self {Self::new()}}

#[derive(Serialize, Deserialize, PartialOrd, PartialEq, Clone, Hash, Ord, Eq)]
pub struct Endpoint(pub OrangeName, pub Url);
impl std::fmt::Debug for Endpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Endpoint({:?}, {})", self.0, self.1)
    }
}

#[derive(Debug)]
pub struct OrangeResolver;
impl OrangeResolver {
    pub async fn sign(&mut self, secret: &OrangeSecret, payload: &[u8]) -> Result<OrangeSignature, Error> {
        Ok(match secret {
            OrangeSecret::Temporary(key) => OrangeSignature::Temporary(key.easy_sign(payload))
        })
    }
    pub async fn verify(&mut self, name: &OrangeName, sig: &OrangeSignature, payload: &[u8], _when: Option<DateTime>) -> Result<(), Error> {
        match sig {
            OrangeSignature::Temporary(sig) => name.0.easy_verify(sig, payload).map_err(ResolutionError::from)?
        }
        Ok(())
    }
    pub async fn secret_keys(&mut self, secret: &OrangeSecret, tag: Option<&str>, _when: Option<DateTime>) -> Result<Vec<(String, SecretKey)>, Error> {
        match tag {
            Some(tag) if tag != "easy_access_com" => Ok(Vec::new()),
            _ => Ok(vec![("easy_access_com".to_string(), secret.key())]),
        }
    }
    pub async fn keys(&mut self, name: &OrangeName, tag: Option<&str>, _when: Option<DateTime>) -> Result<Vec<(String, PublicKey)>, Error> {
        match tag {
            Some(tag) if tag != "easy_access_com" => Ok(Vec::new()),
            _ => Ok(vec![("easy_access_com".to_string(), name.0)]),
        }
    }
    pub async fn endpoints(&mut self, _name: &OrangeName, tag: Option<&str>, _when: Option<DateTime>) -> Result<Vec<(String, Endpoint)>, Error> {
        match tag {
            Some(tag) if tag != "default" => Ok(Vec::new()),
            _ => Ok(vec![("default".to_string(), Endpoint(
                OrangeName::from_str(ORANGEME_NAME).unwrap(),
                Url::from_str(ORANGEME_URI).unwrap()
            ))]),
        }
    }

    pub async fn key(&mut self, name: &OrangeName, tag: Option<&str>, when: Option<DateTime>) -> Result<PublicKey, Error> {
        Ok(self.keys(name, tag, when).await?.first().ok_or(Error::Resolution(format!("Missing Key: {}", tag.unwrap_or("Any"))))?.1)
    }
    pub async fn endpoint(&mut self, name: &OrangeName, tag: Option<&str>, when: Option<DateTime>) -> Result<Endpoint, Error> {
        Ok(self.endpoints(name, tag, when).await?.first().ok_or(Error::Resolution(format!("Missing Endpoint: {}", tag.unwrap_or("Any"))))?.1.clone())
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, Hash)]
pub struct Signed<T>(OrangeName, OrangeSignature, T);
impl<T: Hash + Serialize + for<'a> Deserialize<'a> + Clone + Debug> Signed<T> {
    pub async fn new(resolver: &mut OrangeResolver, secret: &OrangeSecret, inner: T) -> Result<Self, Error> {
        let signature = resolver.sign(secret, EasyHash::core_hash(&inner).as_ref()).await?;
        Ok(Signed(secret.name(), signature, inner))
    }
    pub fn into_inner(self) -> T {self.2}
    pub fn signer(&self) -> &OrangeName {&self.0}
    pub async fn verify(&self, resolver: &mut OrangeResolver, when: Option<DateTime>) -> Result<OrangeName, Error> {
        resolver.verify(&self.0, &self.1, EasyHash::core_hash(&self.2).as_ref(), when).await?;
        Ok(self.0.clone())
    }
}
impl<T: Hash + Serialize + for<'a> Deserialize<'a> + Clone + Debug> AsRef<T> for Signed<T> {fn as_ref(&self) -> &T {&self.2}}
