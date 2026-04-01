use secp256k1::schnorr::Signature as SchnorrSignature;
use secp256k1::{Keypair, SECP256K1};
use secp256k1::ellswift::{Party, ElligatorSwift};

use chacha20_poly1305::{ChaCha20Poly1305, Nonce, Key as ChaChaKey};
use serde::{Serialize, Deserialize};
use serde::ser::Serializer;
use serde::de::Deserializer;

use super::{AirHash, Error};

use std::hash::{Hasher, Hash};
use std::ops::Deref;
use std::fmt::Debug;

pub use secp256k1::rand;
pub(crate) use secp256k1::Error as E;

const DATA: &str = "easy_secp256k1_ellswift_xonly_ecdh";

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Hash)]
pub struct Signature(SchnorrSignature);

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Ord, PartialOrd, Hash)]
pub struct PublicKey(secp256k1::PublicKey);
impl PublicKey {
    pub fn verify(&self, signature: &Signature, payload: &[u8]) -> Result<(), Error> {
        Ok(signature.0.verify(
            AirHash::hash(payload).as_ref(),
            &self.0.x_only_public_key().0
        )?)
    }

    pub fn encrypt(&self, mut payload: Vec<u8>) -> Vec<u8> {
        let secret = SecretKey::new();
        let mine = ElligatorSwift::from_pubkey(secret.public_key().0);
        let theirs = ElligatorSwift::from_pubkey(self.0);
        let ecdh_sk = ElligatorSwift::shared_secret(mine, theirs, secret.0, Party::Initiator, Some(DATA.as_bytes()));
        let key = ChaChaKey::new(ecdh_sk.to_secret_bytes());
        [
            mine.to_array().to_vec(),
            ChaCha20Poly1305::new(key, Nonce::new([0; 12])).encrypt(&mut payload, None).to_vec(),
            payload
        ].concat()
    }
}

impl std::fmt::Display for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result { write!(f, "{}", self.0) }
}

impl std::str::FromStr for PublicKey {
    type Err = Error;
    fn from_str(s: &str) -> Result<PublicKey, Error> {
        Ok(PublicKey(secp256k1::PublicKey::from_str(s)?))
    }
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub struct SecretKey(secp256k1::SecretKey);
impl SecretKey {
    pub fn new() -> Self {
        SecretKey(secp256k1::SecretKey::new(&mut secp256k1::rand::rng()))
    }
    pub fn public_key(&self) -> PublicKey {
        PublicKey(self.0.public_key(SECP256K1))
    }

    pub fn sign(&self, payload: &[u8]) -> Signature {
        let keypair = Keypair::from_secret_key(SECP256K1, &self.0);
        Signature(SECP256K1.sign_schnorr(AirHash::hash(payload).as_ref(), &keypair))
    }

    pub fn decrypt(&self, payload: &[u8]) -> Result<Vec<u8>, Error> {
        if payload.len() < 64+16 {return Err(Error::InvalidMessage);}
        let theirs = ElligatorSwift::from_array(payload[0..64].try_into().or(Err(Error::InvalidMessage))?);
        let tag: [u8; 16] = payload[64..64+16].try_into().or(Err(Error::InvalidMessage))?;
        let mut payload = payload[64+16..].to_vec();

        let mine = ElligatorSwift::from_pubkey(self.public_key().0);
        let ecdh_sk = ElligatorSwift::shared_secret(theirs, mine, self.0, Party::Responder, Some(DATA.as_bytes()));
        let key = ChaChaKey::new(ecdh_sk.to_secret_bytes());

        ChaCha20Poly1305::new(key, Nonce::new([0; 12])).decrypt(&mut payload, tag, None).map_err(|_| Error::InvalidMessage)?;
        Ok(payload)
    }

    /// Hashes the current key with the path item, (key, path) = child_key
    /// /1020/0/234 is not the same as /1020/0234
    pub fn derive<H: Hash>(&self, path: &[H]) -> Self {
        let mut key = self.0;
        for p in path {
            let bytes = super::HashReader::read(p);
            key = secp256k1::SecretKey::from_byte_array(
                *AirHash::hash(&[&key.secret_bytes() as &[u8], &bytes].concat()).as_ref()
            ).unwrap();
        }
        SecretKey(key)
    }
}
impl Hash for SecretKey {fn hash<H: Hasher>(&self, state: &mut H) {state.write(&self.0.secret_bytes());}}
impl Default for SecretKey {fn default() -> Self {Self::new()}}

#[derive(Debug, Hash, PartialEq, Eq)]
pub struct Signed<H: Hash + Debug>{
    signer: PublicKey,
    signature: Signature,
    signed: H
}
impl<H: Hash + Debug> Signed<H> {
    pub fn new(signer: &SecretKey, payload: H) -> Self {
        let bytes = super::HashReader::read(&payload);
        Signed{signer: signer.public_key(), signature: signer.sign(&bytes), signed: payload}
    }

    pub fn verify(&self, signer: Option<PublicKey>) -> Result<PublicKey, Error> {
        if let Some(signer) = signer && signer != self.signer {Err(Error::InvalidSignature)?}
        self.signer.verify(&self.signature, &super::HashReader::read(&self.signed))?;
        Ok(self.signer)
    }
    pub fn signer(&self) -> PublicKey {self.signer}
    pub fn into_inner(self) -> H {self.signed}
}
impl<H: Hash + Debug> Deref for Signed<H> {
    type Target = H;
    fn deref(&self) -> &H {&self.signed}
}
impl<H: Hash + Debug + Clone> Clone for Signed<H> {
    fn clone(&self) -> Self {Signed{
        signer: self.signer, signature: self.signature.clone(), signed: self.signed.clone()
    }}
}
impl<H: Hash + Debug + Serialize> Serialize for Signed<H> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        (&self.signer, &self.signature, &self.signed).serialize(serializer)
    }
}
impl<'de, H: Hash + Debug + Deserialize<'de>> Deserialize<'de> for Signed<H> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        <(PublicKey, Signature, H)>::deserialize(deserializer).map(|(signer, signature, signed)|
            Signed{signer, signature, signed}
        )
    }
}
impl<H: Hash + Debug> AsRef<H> for Signed<H> {fn as_ref(&self) -> &H {&self.signed}}

#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
pub enum Key {Secret(SecretKey), Public(PublicKey)}
impl Hash for Key {fn hash<H: Hasher>(&self, state: &mut H) {self.public_key().hash(state);}}
impl PartialEq for Key {fn eq(&self, other: &Self) -> bool {self.public_key() == other.public_key()}}
impl Eq for Key {}
impl Key {
    pub fn public_key(&self) -> PublicKey {match self {
        Key::Secret(key) => key.public_key(),
        Key::Public(key) => *key
    }}
    pub fn secret_key(&self) -> Option<SecretKey> {match self {
        Key::Secret(key) => Some(*key),
        Key::Public(_) => None 
    }}
    pub fn merge(self, other: Self) -> Option<Self> {
        if self != other {return None;} 
        Some(self.secret_key().or(other.secret_key()).map(Key::Secret).unwrap_or(self))
    }
}

#[test]
fn signature() {
    let signer = SecretKey::new();
    let signed = Signed::new(&signer, b"my message");
    signed.verify(Some(signer.public_key())).unwrap();
}

#[test]
fn encryption() {
    let secret_key = SecretKey::new();
    let public_key = secret_key.public_key();

    let message = b"my message".to_vec();
    let payload = public_key.encrypt(message.clone());

    assert_eq!(message, secret_key.decrypt(&payload).unwrap());
}
