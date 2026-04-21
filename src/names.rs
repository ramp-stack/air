use bitcoin_hashes::sha256::Midstate;
use bitcoin_hashes::sha256t::{self, Tag};

use serde::{Serialize, Deserialize};
use serde::ser::Serializer;
use serde::de::Deserializer;

use std::str::FromStr;
use std::hash::Hash;
use std::fmt::Debug;

pub mod secp256k1;

const ORANGEME_NAME: &str = "03273e58dff6f2e5334c526b0dd0100d20e1ac4bfa22dfd904725eef63931e4853";
const ORANGEME_URL: &str = if cfg!(test) {"0.0.0.0:5702"} else {"air.orange.me:5702"};

pub fn now() -> u64 {chrono::Utc::now().timestamp_millis() as u64}

#[derive(Debug)]
pub enum Error {
    Secp256k1(secp256k1::E),
    InvalidMessage,
    MissingPermissions(Vec<Id>),
    InvalidSignature
}
impl std::error::Error for Error {}
impl std::fmt::Display for Error {fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {write!(f, "{self:?}")}}
impl From<secp256k1::E> for Error {fn from(e: secp256k1::E) -> Self {Error::Secp256k1(e)}}

struct AirTag;
impl Tag for AirTag {
    const MIDSTATE: Midstate = Midstate::hash_tag(b"AIR_NAMES");
}
type AirHash = sha256t::Hash<AirTag>;

#[derive(Default)]
pub struct HashReader(Vec<u8>);
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

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Copy)]
#[derive(serde_with::SerializeDisplay)]
#[derive(serde_with::DeserializeFromStr)]
pub struct Id([u8; 32]);
impl AsRef<[u8]> for Id {fn as_ref(&self) -> &[u8] {&self.0}}
impl std::ops::Deref for Id {type Target = [u8; 32]; fn deref(&self) -> &Self::Target {&self.0}}
impl std::ops::DerefMut for Id {fn deref_mut(&mut self) -> &mut Self::Target {&mut self.0}}
impl From<[u8; 32]> for Id {fn from(id: [u8; 32]) -> Self {Id(id)}}
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

#[derive(Clone, Copy, Debug, Hash, Ord, Eq, PartialOrd, PartialEq)]
#[derive(serde_with::SerializeDisplay)]
#[derive(serde_with::DeserializeFromStr)]
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
    path: Vec<Id>,
    temporary: secp256k1::SecretKey,
}
impl Secret {
    pub fn new() -> Self {
        let temporary = secp256k1::SecretKey::new();
        Secret{name: Name(temporary.public_key()), path: vec![], temporary}
    }
    pub fn harden(&self) -> secp256k1::SecretKey {self.temporary.derive(&self.path)}
    pub fn name(&self) -> Name {self.name}
    pub fn path(&self) -> &Vec<Id> {&self.path}
    pub fn public(&self) -> Public {Public(self.temporary.public_key())}
    pub fn sign(&self, payload: &[u8]) -> Result<Signature, Error> {
        Ok(Signature(self.temporary.sign(payload)))
    }

    pub fn decrypt(&self, _datetime: Option<u64>, path: &[Id], payload: &[u8]) -> Result<Vec<u8>, Error> {
        let _path = path.strip_prefix(self.path.as_slice()).ok_or(Error::MissingPermissions(path.to_vec()))?;
        self.temporary.decrypt(payload)
    }

    pub fn derive(&self, path: &[Id]) -> Result<Self, Error> {
        Ok(Secret{
            name: self.name,
            path: [&self.path, path].concat(),
            temporary: self.temporary
        })
    }
}
impl Default for Secret {fn default() -> Self {Self::new()}}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Hash)]
pub struct Signature(secp256k1::Signature);

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub struct Public(secp256k1::PublicKey);

impl Public {
    pub fn verify(&mut self, _path: &[Id], sig: &Signature, payload: &[u8]) -> Result<(), Error> {
        self.0.verify(&sig.0, payload).map_err(|_| Error::InvalidSignature)
    }

    pub fn encrypt(&mut self, _path: &[Id], payload: Vec<u8>) -> Result<Vec<u8>, Error> {
        Ok(self.0.encrypt(payload))
    }
}

#[derive(Default, Debug)]
pub struct Resolver;
impl Resolver {
    pub async fn verify(&mut self, name: &Name, _datetime: Option<u64>, path: &[Id], sig: &Signature, payload: &[u8]) -> Result<(), Error> {
        self.public(name).await?.verify(path, sig, payload)
    }

    pub async fn encrypt(&mut self, name: &Name, path: &[Id], payload: Vec<u8>) -> Result<Vec<u8>, Error> {
        self.public(name).await?.encrypt(path, payload)
    }

    pub async fn public(&mut self, name: &Name) -> Result<Public, Error> {
        Ok(Public(name.0))
    }

    pub async fn url(&mut self, _name: &Name) -> Result<String, Error> {
        Ok(ORANGEME_URL.to_string())
    }

    pub async fn air_servers(&mut self, _name: &Name) -> Result<Vec<Name>, Error> {
        Ok(vec![Name::from_str(ORANGEME_NAME).unwrap()])
    }
}

#[derive(Debug, Hash, PartialEq, Eq)]
pub struct Signed<H: Hash + Debug>(Name, u64, Vec<Id>, Signature, H);
impl<H: Hash + Debug> Signed<H> {
    pub fn new(secret: &Secret, payload: H) -> Result<Self, Error> {
        let bytes = HashReader::read(&payload);
        Ok(Signed(secret.name, now(), secret.path().to_vec(), secret.sign(&bytes)?, payload))
    }
    pub async fn verify(&self, resolver: &mut Resolver, signer: Option<&Name>, path: Option<&[Id]>) -> Result<Name, Error> {
        let bytes = HashReader::read(&self.4);
        if let Some(signer) = signer && &self.0 != signer {Err(Error::InvalidSignature)?}
        if let Some(path) = path && self.2 != path {Err(Error::InvalidSignature)?}
        resolver.verify(&self.0, Some(self.1), &self.2, &self.3, &bytes).await?;
        Ok(self.0)
    }
    pub fn signer(&self) -> Name {self.0}
    pub fn datetime(&self) -> u64 {self.1}
    pub fn path(&self) -> &[Id] {&self.2}
    pub fn into_inner(self) -> H {self.4}
}
impl<H: Hash + Debug + Clone> Clone for Signed<H> {
    fn clone(&self) -> Self {Signed(self.0, self.1, self.2.clone(), self.3.clone(), self.4.clone())}
}
impl<H: Hash + Debug + Serialize> Serialize for Signed<H> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        (&self.0, &self.1, &self.2, &self.3, &self.4).serialize(serializer)
    }
}
impl<'de, H: Hash + Debug + Deserialize<'de>> Deserialize<'de> for Signed<H> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        <(Name, u64, Vec<Id>, Signature, H)>::deserialize(deserializer).map(|(a, b, c, d, e)|
            Signed(a, b, c, d, e)
        )
    }
}
impl<H: Hash + Debug> AsRef<H> for Signed<H> {fn as_ref(&self) -> &H {&self.4}}

#[cfg(test)]
mod test {
    use super::*;
    use std::future::Future;
    use std::sync::Arc;
    use std::task::{Context, Poll, Wake};
    use std::thread::{self, Thread};
    use core::pin::pin;

    /// A waker that wakes up the current thread when called.
    struct ThreadWaker(Thread);

    impl Wake for ThreadWaker {
        fn wake(self: Arc<Self>) {
            self.0.unpark();
        }
    }

    /// Run a future to completion on the current thread.
    fn block_on<T>(fut: impl Future<Output = T>) -> T {
        // Pin the future so it can be polled.
        let mut fut = pin!(fut);

        // Create a new context to be passed to the future.
        let t = thread::current();
        let waker = Arc::new(ThreadWaker(t)).into();
        let mut cx = Context::from_waker(&waker);

        // Run the future to completion.
        loop {
            match fut.as_mut().poll(&mut cx) {
                Poll::Ready(res) => return res,
                Poll::Pending => thread::park(),
            }
        }
    }

    #[test]
    pub fn encryption() {
        let secret = Secret::new();
        let name = secret.name();

        let id = Id::random();

        let m = vec![1, 2, 3];
        let c = block_on(Resolver.encrypt(&name, &[id], m.clone())).unwrap();
        assert_eq!(m, secret.decrypt(None, &[id], &c).unwrap())
    }

    #[test]
    pub fn signature() {
        let secret = Secret::new();
        let name = secret.name();

        let id = Id::random();

        let m = vec![1, 2, 3];
        let s = secret.derive(&[id]).unwrap().sign(&m).unwrap();
        block_on(Resolver.verify(&name, None, &[id], &s, &m)).unwrap();
    }
}
