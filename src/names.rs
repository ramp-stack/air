use bitcoin_hashes::sha256::Midstate;
use bitcoin_hashes::sha256t::{self, Tag};

use serde::{Serialize, Deserialize};
use serde::ser::Serializer;
use serde::de::Deserializer;

use std::collections::HashMap;
use std::str::FromStr;
use std::hash::Hash;
use std::fmt::Debug;

mod fschacha20poly1305;
pub mod secp256k1;

pub use secp256k1::{Sink, Drain, Message};

const TAG: &str = "AIR_NAMES";
const ORANGEME_NAME: &str = "03273e58dff6f2e5334c526b0dd0100d20e1ac4bfa22dfd904725eef63931e4853";
const ORANGEME_URL: &str = if cfg!(test) {"ws://0.0.0.0:5702"} else {"ws://air.orange.me:5702"};

pub fn now() -> u64 {chrono::Utc::now().timestamp_nanos_opt().unwrap() as u64}

///30 minutes
pub const TIMEOUT: u64 = 60_000_000_000;

#[derive(Debug, PartialEq)]
pub enum Error {
    ///This occures if an Identity has not been refreshed in the last TIMEOUT nano seconds
    InvalidPublicKey,
    IdentityExpired,
    MissingPermissions(Vec<Id>),
    ValidationFailed,
    DecryptionFailed 
}
impl std::error::Error for Error {}
impl std::fmt::Display for Error {fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {write!(f, "{self:?}")}}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Copy)]
#[derive(serde_with::SerializeDisplay)]
#[derive(serde_with::DeserializeFromStr)]
pub struct Id([u8; 32]);
impl AsRef<[u8]> for Id {fn as_ref(&self) -> &[u8] {&self.0}}
impl std::ops::Deref for Id {type Target = [u8; 32]; fn deref(&self) -> &Self::Target {&self.0}}
impl std::ops::DerefMut for Id {fn deref_mut(&mut self) -> &mut Self::Target {&mut self.0}}
impl From<[u8; 32]> for Id {fn from(id: [u8; 32]) -> Self {Id(id)}}
impl From<Id> for [u8; 32] {fn from(val: Id) -> Self {val.0}}
impl From<u64> for Id {fn from(id: u64) -> Self {
    let mut arr = [0u8; 32];
    arr[0..8].copy_from_slice(&id.to_le_bytes());
    Id(arr)
}}
impl Id {
    pub const MAX: Id = Id([u8::MAX; 32]);
    pub const MIN: Id = Id([u8::MIN; 32]);
    pub fn hash<H: Hash + ?Sized>(h: &H) -> Self {
        Id(*AirHash::hash(&HashReader::read(h)).as_ref())
    }
    pub fn random() -> Self {Id(secp256k1::rand::random())}
}
impl std::fmt::Display for Id {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}
impl std::fmt::Debug for Id {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}
impl std::str::FromStr for Id {
    type Err = hex::FromHexError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Id(hex::decode(s)?.try_into().map_err(|_| hex::FromHexError::InvalidStringLength)?))
    }
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, Hash, Ord, Eq, PartialOrd, PartialEq)]
pub struct Name(secp256k1::PublicKey);
impl Name {
    pub fn orange_me() -> Name {Name::from_str(ORANGEME_NAME).unwrap()}
}
impl std::fmt::Display for Name {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}
impl std::str::FromStr for Name {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Name(secp256k1::PublicKey::from_str(s)?))
    }
}


#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Secret {
    name: Name,
    temporary: secp256k1::SecretKey,
    path: Vec<Id>,
}
impl Secret {
    pub fn name(&self) -> Name {self.name}
    pub fn path(&self) -> &Vec<Id> {&self.path}
    pub fn harden(&self) -> secp256k1::SecretKey {self.temporary.derive(&self.path)}

    pub fn new() -> Self {
        let temporary = secp256k1::SecretKey::new();
        Secret{name: Name(temporary.public_key()), path: vec![], temporary}
    }

    pub fn derive(&self, path: &[Id]) -> Self {
        Secret{
            name: self.name,
            path: [&self.path, path].concat(),
            temporary: self.temporary
        }
    }

    pub fn sign(&self, id: Id) -> Signature {Signature::new(self, id)}
    pub fn decrypt(&self, encrypted: Encrypted) -> Result<Vec<u8>, Error> {
        self.temporary.decrypt(encrypted.0)
    }
}
impl Default for Secret {fn default() -> Self {Self::new()}}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Hash)]
pub struct Signature(secp256k1::Signature);
impl Signature {
    pub fn new(secret: &Secret, id: Id) -> Self {
        Signature(secp256k1::Signature::new(&secret.temporary, Id::hash(&(id, &secret.path))))
    }

    pub fn verify(&self, identity: &Identity, path: &[Id], id: Id) -> Result<(), Error> {
        self.0.verify(&identity.name.0, Id::hash(&(id, path.to_vec())))
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Identity {
    name: Name,
    servers: Vec<Name>,
    url: Vec<String>,
    #[serde(flatten)]
    data: HashMap<String, String>
}

impl Identity {
    pub fn name(&self) -> Name {self.name}

    pub fn verify(&self, path: &[Id], signature: &Signature, id: Id) -> Result<(), Error> {
        signature.verify(self, path, id)
    }

    ///You always want to encrypt something to the identity now
    pub fn encrypt(&self, _path: &[Id], payload: Vec<u8>) -> Encrypted {
        Encrypted(self.name.0.encrypt(payload))
    }

    ///If an Identity has a server it means that they actively listen to missives there
    pub fn servers(&self) -> &Vec<Name> {&self.servers}

    ///If an Identity has a url it means they have a chandler running at that location
    pub fn url(&self) -> &Vec<String> {&self.url}

    pub fn get(&self, key: &str) -> Option<&String> {self.data.get(key)}
}

#[derive(Clone, Debug)]
pub struct Resolver();
impl Resolver {
    pub fn start() -> Self {Resolver()}

    pub async fn resolve(&self, name: Name, _timestamp: Option<u64>) -> Identity {
        if name == Name::orange_me() {
            Identity{name, url: vec![ORANGEME_URL.to_string()], servers: vec![], data: HashMap::new()}
        } else {
            Identity{name, url: vec![], servers: vec![Name::orange_me()], data: HashMap::new()}
        }
    }
}

#[derive(Debug, Hash, PartialEq, Eq)]
pub struct Signed<I: Hash + Debug>{
    pub signer: Name,
    pub signature: Signature,
    pub payload: I
}
impl<I: Hash + Debug> Signed<I> {
    pub fn new(signer: &Secret, payload: I) -> Self {
        Signed{signer: signer.name(), signature: signer.sign(Id::hash(&payload)), payload}
    }

    pub fn verify(&self, identity: &Identity, path: &[Id]) -> Result<(), Error> {
        if identity.name() != self.signer {Err(Error::ValidationFailed)?}
        self.signature.verify(identity, path, Id::hash(&self.payload))
    }
}
impl<H: Hash + Debug + Clone> Clone for Signed<H> {
    fn clone(&self) -> Self {Signed{signer: self.signer, signature: self.signature.clone(), payload: self.payload.clone()}}
}
impl<H: Hash + Debug + Serialize> Serialize for Signed<H> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        (&self.signer, &self.signature, &self.payload).serialize(serializer)
    }
}
impl<'de, H: Hash + Debug + Deserialize<'de>> Deserialize<'de> for Signed<H> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        <(Name, Signature, H)>::deserialize(deserializer).map(|(signer, signature, payload)| Signed{signer, signature, payload})
    }
}
impl<H: Hash + Debug> AsRef<H> for Signed<H> {fn as_ref(&self) -> &H {&self.payload}}



#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Encrypted(secp256k1::Encrypted);

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Init(secp256k1::Init);//Will contain a secp256k1 key encrypted to the path of the recipient(BSL is an alt to ECDH Key Exchange)


///Pass init to the remote party
///Messages do not have to be received or exchanged one after the other
///But they do have to be decrypted in the same order they were encrypted
pub struct EncryptionStream(secp256k1::EncryptionStream);
impl EncryptionStream {
    pub fn new(recipient: &Identity, _path: &[Id]) -> Result<(Self, Init), Error> {
        let (stream, init) = secp256k1::EncryptionStream::new(&recipient.name.0);
        Ok((Self(stream), Init(init)))
    }

    //Will error if it cannot decrypt shared key.
    pub fn receive(secret: &Secret, init: Init) -> Result<Self, Error> {
        Ok(Self(secp256k1::EncryptionStream::receive(&secret.temporary, init.0)))
    }

    pub fn encrypt(&mut self, data: Vec<u8>) -> Message {
        self.0.encrypt(data)
    }

    pub fn decrypt(&mut self, message: Message) -> Result<Vec<u8>, Error> {
        self.0.decrypt(message)
    }

    pub fn split(self) -> (Sink, Drain) {self.0.split()}
}

struct AirTag;
impl Tag for AirTag {
    const MIDSTATE: Midstate = Midstate::hash_tag(TAG.as_bytes());
}
type AirHash = sha256t::Hash<AirTag>;

#[derive(Default)]
struct HashReader(Vec<u8>);
impl core::hash::Hasher for HashReader {
    fn finish(&self) -> u64 {panic!("NOOP");}
    fn write(&mut self, bytes: &[u8]) {self.0.extend(bytes);}
}
impl HashReader {
    pub fn read<H: Hash + ?Sized>(h: &H) -> Vec<u8> {
        let mut hasher = HashReader::default();
        h.hash(&mut hasher);
        hasher.0
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[tokio::test]
    async fn encryption() {
        let secret = Secret::new();
        let name = secret.name();
        let resolver = Resolver::start();
        let identity = resolver.resolve(name, None).await;

        let m = b"hello".to_vec();
        let c = identity.encrypt(&[], m.clone());
        assert_eq!(m, secret.decrypt(c).unwrap());
    }

    #[tokio::test]
    async fn signature() {
        let secret = Secret::new();
        let name = secret.name();

        let resolver = Resolver::start();
        let identity = resolver.resolve(name, None).await;

        let path = &[Id::random()];
        let id = Id::random();
        let secret = secret.derive(path);
        let signature = secret.sign(id);
        identity.verify(path, &signature, id).unwrap();
    }
}
