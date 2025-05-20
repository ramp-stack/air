use secp256k1::{SecretKey, PublicKey};
use std::hash::Hash;
use std::fmt::Debug;
use url::Url;
use chrono::{DateTime, Utc};
use serde::{Serialize, Deserialize};
use dyn_clone::{DynClone, clone_trait_object};

mod key;
pub use key::{LiquidSecret, DidLiquid};

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
impl std::error::Error for Error {}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

pub trait DidSecret: DynClone + std::any::Any {
    fn method(&self) -> &'static str;
    fn did(&self) -> Did;
    fn key(&self, tag: &str) -> Result<SecretKey, Error>;
}
clone_trait_object!(DidSecret);

#[derive(Clone, Hash, Ord, Eq, PartialOrd, PartialEq)]
#[derive(serde_with::SerializeDisplay)]
#[derive(serde_with::DeserializeFromStr)]
pub struct Did(pub String, pub String);
impl std::fmt::Display for Did {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "did:{}:{}", self.0, self.1)
    }
}
impl Debug for Did {fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {write!(f, "did:{}:{:.10}", self.0, self.1)}}

impl std::str::FromStr for Did {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let split = s.split(":").collect::<Vec<_>>();
        if split.len() != 3 || split[0] != "did" {return Err("invalid".to_string());}
        Ok(Did(split[1].to_string(), split[2].to_string()))
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Hash)]
pub struct Signature(String);

#[derive(Serialize, Deserialize, PartialOrd, PartialEq, Clone, Hash, Ord, Eq)]
pub struct Endpoint(pub Did, pub Url);
impl std::fmt::Debug for Endpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Endpoint({:?}, {})", self.0, self.1)
    }
}

#[async_trait::async_trait(?Send)]
pub trait DidResolver {
    async fn sign(&mut self, secret: Box<dyn DidSecret>, payload: &[u8]) -> Result<Signature, Error>;
    async fn verify(&mut self, did: &Did, sig: &Signature, payload: &[u8], when: Option<DateTime::<Utc>>) -> Result<(), Error>;
    async fn keys(&mut self, did: &Did, tag: Option<&str>, when: Option<DateTime::<Utc>>) -> Result<Vec<(String, PublicKey)>, Error>;
    async fn endpoints(&mut self, did: &Did, tag: Option<&str>, when: Option<DateTime::<Utc>>) -> Result<Vec<(String, Endpoint)>, Error>;
    
    async fn key(&mut self, did: &Did, tag: Option<&str>, when: Option<DateTime::<Utc>>) -> Result<PublicKey, Error> {
        Ok(self.keys(did, tag, when).await?.last().ok_or(Error::Resolution(format!("MissingKey({})", tag.unwrap_or("any"))))?.1)
    }

    async fn endpoint(&mut self, did: &Did, tag: Option<&str>, when: Option<DateTime::<Utc>>) -> Result<Endpoint, Error> {
        Ok(self.endpoints(did, tag, when).await?.last().ok_or(Error::Resolution(format!("MissingEndpoint({})", tag.unwrap_or("any"))))?.1.clone())
    }
}

//  #[derive(Serialize, Deserialize, Hash)]
//  pub struct Signed<T>(Did, Signature, T);

//  impl<T: Hash> Signed<T> {
//      pub async fn new(&self, signer: Did, signature: Signature, inner: T) -> Self {
//          Signed(signer, signature, inner)
//      }
//      pub async fn verify(&self, resolver: &mut dyn DidResolver, when: Option<DateTime::<Utc>>) -> Result<Did, Error> {
//          resolver.verify(&self.0, &self.1, EasyHash::core_hash(&self.2).as_ref(), when).await?;
//          Ok(self.0.clone())
//      }
//  }

//  impl<T: Hash> AsRef<T> for Signed<T> {
//      fn as_ref(&self) -> &T {&self.2}
//  }

//  impl<T: Hash> AsMut<T> for Signed<T> {
//      fn as_mut(&mut self) -> &mut T {&mut self.2}
//  }

//  impl<T: Hash + Clone> Clone for Signed<T> {
//      fn clone(&self) -> Self {Signed(self.0.clone(), self.1.clone(), self.2.clone())}
//  }

//  impl<T: Hash + Debug> Debug for Signed<T> {
//      fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
//          f.debug_struct("Signed")
//           .field("signer", &self.0)
//           .field("signature", &self.1)
//           .field("inner", &self.2)
//           .finish()
//      }
//  }
