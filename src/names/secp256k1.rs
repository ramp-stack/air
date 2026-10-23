use secp256k1::schnorr::Signature as SchnorrSignature;
use secp256k1::{Keypair, SECP256K1};
use secp256k1::ellswift::ElligatorSwift;
use serde::{Serialize, Deserialize};
use serde::ser::Serializer;
use serde::de::Deserializer;
pub use secp256k1::ellswift::Party;
use std::hash::{Hasher, Hash};
use std::fmt::Debug;
use super::{Error, Id};
use super::fschacha20poly1305::FSChaCha20Poly1305;

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Signature(SchnorrSignature);
impl Signature {
    pub fn new(key: &SecretKey, id: Id) -> Self {
        let keypair = Keypair::from_secret_key(SECP256K1, &key.0);
        Signature(SECP256K1.sign_schnorr(id.as_ref(), &keypair))
    }

    pub fn verify(&self, key: &PublicKey, id: Id) -> Result<(), Error> {
        self.0
            .verify(id.as_ref(), &key.0.x_only_public_key().0)
            .map_err(|_| Error::ValidationFailed)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Ord, PartialOrd, Hash)]
pub struct PublicKey(secp256k1::PublicKey);
impl PublicKey {
    pub fn verify(&self, signature: &Signature, id: Id) -> Result<(), Error> {
        signature.verify(self, id)
    }

    pub fn encrypt(&self, data: Vec<u8>) -> Vec<u8> {
        let temp = SecretKey::new();
        let shared = temp.shared(self, Some(Party::Initiator));
        let message = Stream::new(shared, Party::Initiator).encrypt(data);
        [temp.public_key().to_vec(), message].concat()
    }

    pub fn derive_risky(&self, path: &[Id]) -> Self {
        let mut key = self.0;
        for id in path {
            let sk = secp256k1::SecretKey::from_byte_array(*Id::hash(&(key, id))).unwrap();
            key = key.add_exp_tweak(SECP256K1, &sk.into()).unwrap();
        }
        PublicKey(key)
    }

    pub fn to_array(self) -> [u8; 64] { ElligatorSwift::from_pubkey(self.0).to_array() }
    pub fn to_vec(self) -> Vec<u8> { self.to_array().to_vec() }
    pub fn from_array(a: [u8; 64]) -> Self {
        Self(secp256k1::PublicKey::from_ellswift(ElligatorSwift::from_array(a)))
    }
    pub fn from_bytes(b: &[u8]) -> Result<Self, Error> {
        Ok(Self::from_array(b.try_into().map_err(|_| Error::InvalidPublicKey)?))
    }
}

impl Serialize for PublicKey {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(&self.to_array())
    }
}

impl<'de> Deserialize<'de> for PublicKey {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Vec::<u8>::deserialize(d).and_then(|b| {
            Self::from_bytes(&b)
                .map_err(|_| serde::de::Error::invalid_length(64, &"Expected a 64 byte array"))
        })
    }
}

impl std::fmt::Display for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result { write!(f, "{}", self.0) }
}

impl std::str::FromStr for PublicKey {
    type Err = Error;
    fn from_str(s: &str) -> Result<PublicKey, Self::Err> {
        Ok(PublicKey(secp256k1::PublicKey::from_str(s).map_err(|_| Error::InvalidPublicKey)?))
    }
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub struct SecretKey(secp256k1::SecretKey);
impl SecretKey {
    pub fn new() -> Self { SecretKey(secp256k1::SecretKey::new(&mut secp256k1::rand::rng())) }
    pub fn public_key(&self) -> PublicKey { PublicKey(self.0.public_key(SECP256K1)) }
    pub fn sign(&self, id: Id) -> Signature { Signature::new(self, id) }
    pub fn decrypt(&self, mut encrypted: Vec<u8>) -> Result<Vec<u8>, Error> {
        if encrypted.len() <= 64 { Err(Error::DecryptionFailed)? }

        let message = encrypted.split_off(64);
        let key = PublicKey::from_array(encrypted.try_into().unwrap());

        let shared = self.shared(&key, Some(Party::Responder));
        Stream::new(shared, Party::Responder).decrypt(message)
    }

    pub fn shared(&self, theirs: &PublicKey, party: Option<Party>) -> Self {
        let mine = self.public_key();
        let mine = ElligatorSwift::from_pubkey(mine.0);
        let theirs = ElligatorSwift::from_pubkey(theirs.0);
        let (party, a, b) = match party {
            Some(Party::Initiator) => (Party::Initiator, mine, theirs),
            Some(Party::Responder) => (Party::Responder, theirs, mine),
            None if mine >= theirs => (Party::Initiator, mine, theirs),
            _ => (Party::Responder, theirs, mine),
        };
        let ecdh_sk = ElligatorSwift::shared_secret(a, b, self.0, party, Some(b"AIR_NAMES"));
        SecretKey(secp256k1::SecretKey::from_byte_array(ecdh_sk.to_secret_bytes()).unwrap())
    }

    pub fn derive(&self, path: &[Id]) -> Self {
        let mut key = self.0;
        for id in path {
            key = secp256k1::SecretKey::from_byte_array(*Id::hash(
                &[&key.secret_bytes() as &[u8], id.as_ref() as &[u8]].concat(),
            ))
            .unwrap();
        }
        SecretKey(key)
    }

    ///Warning providing the returned private key to someone with the public key to this secret key
    ///will result in a comprimise of this secret key
    pub fn derive_risky(&self, path: &[Id]) -> Self {
        let mut key = self.0;
        for id in path {
            key =
                secp256k1::SecretKey::from_byte_array(*Id::hash(&(key.public_key(SECP256K1), id)))
                    .unwrap()
                    .add_tweak(&key.into())
                    .unwrap();
        }
        SecretKey(key)
    }

    pub fn to_array(self) -> [u8; 32] { self.0.secret_bytes() }
    pub fn to_vec(self) -> Vec<u8> { self.to_array().to_vec() }
    pub fn from_array(a: [u8; 32]) -> Result<Self, Error> {
        Ok(Self(secp256k1::SecretKey::from_byte_array(a).map_err(|_| Error::InvalidSecretKey)?))
    }
    pub fn from_bytes(b: &[u8]) -> Result<Self, Error> {
        Self::from_array(b.try_into().map_err(|_| Error::InvalidSecretKey)?)
    }
}
impl Hash for SecretKey {
    fn hash<H: Hasher>(&self, state: &mut H) { state.write(&self.0.secret_bytes()); }
}
impl Default for SecretKey {
    fn default() -> Self { Self::new() }
}

#[derive(Debug, Hash, PartialEq, Eq, Clone)]
pub struct Signed<I: Hash + Debug> {
    pub key: PublicKey,
    pub signature: Signature,
    pub payload: I,
}
impl<I: Hash + Debug> Signed<I> {
    pub fn new(signer: &SecretKey, payload: I) -> Self {
        Signed { key: signer.public_key(), signature: signer.sign(Id::hash(&payload)), payload }
    }

    pub fn verify(&self) -> Result<(), Error> {
        self.signature.verify(&self.key, Id::hash(&self.payload))
    }
}
impl<H: Hash + Debug + Serialize> Serialize for Signed<H> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        (&self.key, &self.signature, &self.payload).serialize(serializer)
    }
}
impl<'de, H: Hash + Debug + Deserialize<'de>> Deserialize<'de> for Signed<H> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        <(PublicKey, Signature, H)>::deserialize(deserializer)
            .map(|(key, signature, payload)| Signed { key, signature, payload })
    }
}
impl<H: Hash + Debug> AsRef<H> for Signed<H> {
    fn as_ref(&self) -> &H { &self.payload }
}

pub struct Sink(FSChaCha20Poly1305);
impl Sink {
    pub fn encrypt(&mut self, mut data: Vec<u8>) -> Vec<u8> {
        let tag = self.0.encrypt(&[], &mut data);
        [tag.to_vec(), data].concat()
    }
}

pub struct Drain(FSChaCha20Poly1305);
impl Drain {
    pub fn decrypt(&mut self, mut message: Vec<u8>) -> Result<Vec<u8>, Error> {
        if message.len() < 17 { Err(Error::DecryptionFailed)? }

        let mut body = message.split_off(16);
        let tag: [u8; 16] = message.try_into().unwrap();
        self.0.decrypt(&[], &mut body, tag).map_err(|_| Error::DecryptionFailed)?;
        Ok(body)
    }
}

//I can use the FsChaCha for length encryption like in BIP324 if needed
pub struct Stream(Sink, Drain);
impl Stream {
    pub fn new(shared: SecretKey, party: Party) -> Self {
        let (sender, receiver) = match party {
            Party::Initiator => (Id::from([u8::MAX; 32]), Id::from([u8::MIN; 32])),
            Party::Responder => (Id::from([u8::MIN; 32]), Id::from([u8::MAX; 32])),
        };
        let sender = FSChaCha20Poly1305::new(shared.derive(&[sender]).0.secret_bytes());
        let receiver = FSChaCha20Poly1305::new(shared.derive(&[receiver]).0.secret_bytes());
        Self(Sink(sender), Drain(receiver))
    }

    pub fn send(public_key: PublicKey) -> (Self, PublicKey) {
        let temp = SecretKey::new();
        let public = temp.public_key();
        let shared = temp.shared(&public_key, Some(Party::Initiator));
        (Stream::new(shared, Party::Initiator), public)
    }

    pub fn receive(secret_key: &SecretKey, public_key: PublicKey) -> Self {
        let shared = secret_key.shared(&public_key, Some(Party::Responder));
        Stream::new(shared, Party::Responder)
    }

    pub fn encrypt(&mut self, data: Vec<u8>) -> Vec<u8> { self.0.encrypt(data) }

    pub fn decrypt(&mut self, message: Vec<u8>) -> Result<Vec<u8>, Error> {
        self.1.decrypt(message)
    }

    pub fn split(self) -> (Sink, Drain) { (self.0, self.1) }
}

#[test]
fn signature() {
    let id = Id::hash(b"hello");
    let signer = SecretKey::new();
    let signed = Signature::new(&signer, id);
    signed.verify(&signer.public_key(), id).unwrap();
}

#[test]
fn encryption() {
    let secret_key = SecretKey::new();
    let public_key = secret_key.public_key();

    let message = b"my message".to_vec();
    let payload = public_key.encrypt(message.clone());

    assert_eq!(message, secret_key.decrypt(payload).unwrap());
}

#[test]
fn extended() {
    let path = [Id::hash("apple"), Id::hash("bannana")];
    let xpriv = SecretKey::new();
    let cpriv = xpriv.derive_risky(&path);

    let xpub = xpriv.public_key();
    let cpub = xpub.derive_risky(&path);

    assert_eq!(cpriv.public_key(), cpub);
}

#[test]
fn stream() {
    let remote = SecretKey::new();
    let rpub = remote.public_key();

    let (mut stream, lpub) = Stream::send(rpub);

    let msg0 = b"hello".to_vec();
    let msg1 = b"I am trying to talk to you".to_vec();
    let msg2 = b"Sorry just saw these messages".to_vec();
    let msg3 = b"I also just don't want to talk to you...".to_vec();

    let mut receiver_stream = Stream::receive(&remote, lpub);

    let message0 = stream.encrypt(msg0.clone());
    let message1 = stream.encrypt(msg1.clone());
    assert_eq!(receiver_stream.decrypt(message0), Ok(msg0));
    assert_eq!(receiver_stream.decrypt(message1), Ok(msg1));

    let message2 = receiver_stream.encrypt(msg2.clone());
    assert_eq!(stream.decrypt(message2), Ok(msg2));

    let message3 = receiver_stream.encrypt(msg3.clone());
    assert_eq!(stream.decrypt(message3), Ok(msg3));
}
