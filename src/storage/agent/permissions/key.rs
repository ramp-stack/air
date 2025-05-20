use easy_secp256k1::{EasySecretKey};
use secp256k1::{SecretKey, PublicKey};

use serde::{Serialize, Deserialize};
use std::hash::{Hasher, Hash};

use super::Error;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum Key {
    Secret(SecretKey),
    Public(PublicKey),
}

impl Key {
    pub fn public_key(&self) -> PublicKey {match self {
        Key::Secret(key) => key.easy_public_key(),
        Key::Public(key) => *key
    }}
    pub fn secret_key(&self) -> Option<SecretKey> {match self {
        Key::Secret(key) => Some(*key),
        Key::Public(_) => None 
    }}
    
    pub fn max(self, other: Self) -> Result<Self, Error> {
        match self != other {
            true => Err(Error::DifferentKeys),
            false => Ok(match &self {
                Key::Secret(_) => self,
                Key::Public(_) => match other {
                    Key::Secret(_) => other,
                    Key::Public(_) => self
                }
            })
        }
    }
    pub fn to_public(self) -> Self {Key::Public(self.public_key())}
    pub fn min(self, secret: bool, error: &str) -> Result<Self, Error> {
        match secret && matches!(self, Key::Public(_)) {
            true => Err(Error::MissingPerms(error.to_string())),
            false => Ok(self.to_public())
        }
    }
}

impl Hash for Key {fn hash<H: Hasher>(&self, state: &mut H) {match self {
    Key::Secret(key) => state.write(&key.secret_bytes()),
    Key::Public(key) => key.hash(state)
}}}
impl PartialEq for Key {fn eq(&self, other: &Self) -> bool {
    self.public_key() == other.public_key()
}}
impl Eq for Key {}
