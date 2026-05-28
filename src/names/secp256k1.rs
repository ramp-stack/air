use secp256k1::schnorr::Signature as SchnorrSignature;
use secp256k1::{Keypair, SECP256K1};
use secp256k1::ellswift::ElligatorSwift;

use serde::{Serialize, Deserialize};
use serde::ser::Serializer;
use serde::de::Deserializer;

use super::{TAG, Error, Id};

use std::hash::{Hasher, Hash};
use std::fmt::Debug;

use super::fschacha20poly1305::FSChaCha20Poly1305;

pub(crate) use secp256k1::rand;
use secp256k1::ellswift::Party;

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Signature(SchnorrSignature);
impl Signature {
    pub fn new(key: &SecretKey, id: Id) -> Self {
        let keypair = Keypair::from_secret_key(SECP256K1, &key.0);
        Signature(SECP256K1.sign_schnorr(id.as_ref(), &keypair))
    }

    pub fn verify(&self, key: &PublicKey, id: Id) -> Result<(), Error> {
        self.0.verify(id.as_ref(), &key.0.x_only_public_key().0).map_err(|_| Error::ValidationFailed)
    }
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Ord, PartialOrd, Hash)]
pub struct PublicKey(secp256k1::PublicKey);
impl PublicKey {
    pub fn verify(&self, signature: &Signature, id: Id) -> Result<(), Error> {signature.verify(self, id)}
    pub fn encrypt(&self, data: Vec<u8>) -> Encrypted {
        let (mut stream, init) = EncryptionStream::new(self);
        let message = stream.encrypt(data);
        Encrypted(init, message)
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
    pub fn new() -> Self {
        SecretKey(secp256k1::SecretKey::new(&mut secp256k1::rand::rng()))
    }
    pub fn public_key(&self) -> PublicKey {PublicKey(self.0.public_key(SECP256K1))}
    pub fn sign(&self, id: Id) -> Signature {Signature::new(self, id)}
    pub fn decrypt(&self, encrypted: Encrypted) -> Result<Vec<u8>, Error> {
        let mut stream = EncryptionStream::receive(self, encrypted.0);
        stream.decrypt(encrypted.1)
    }

    pub fn derive(&self, path: &[Id]) -> Self {
        let mut key = self.0;
        for id in path {
            key = secp256k1::SecretKey::from_byte_array(
                *Id::hash(&[&key.secret_bytes() as &[u8], id.as_ref() as &[u8]].concat())
            ).unwrap();
        }
        SecretKey(key)
    }
}
impl Hash for SecretKey {fn hash<H: Hasher>(&self, state: &mut H) {state.write(&self.0.secret_bytes());}}
impl Default for SecretKey {fn default() -> Self {Self::new()}}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Encrypted(Init, Message);

///The inital data required for decryption
#[derive(Clone, Debug)]
pub struct Init(ElligatorSwift);
//  impl Init {
//      fn to_array(&self) -> [u8; 64] {self.0.to_array()}
//      fn from_array(array: [u8; 64]) -> Self {Self(ElligatorSwift::from_array(array))}
//  }
impl Serialize for Init {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {s.serialize_bytes(&self.0.to_array())}
}

impl<'de> Deserialize<'de> for Init {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {<&[u8]>::deserialize(d).and_then(|b| {
        Ok(Self(ElligatorSwift::from_array(b.try_into().map_err(|_| serde::de::Error::invalid_length(64, &"Expected a 64 byte array"))?)))
    })}
}

#[derive(Debug, Hash, PartialEq, Eq)]
pub struct Signed<I: Hash + Debug>{
    pub key: PublicKey,
    pub signature: Signature,
    pub payload: I
}
impl<I: Hash + Debug> Signed<I> {
    pub fn new(signer: &SecretKey, payload: I) -> Self {
        Signed{key: signer.public_key(), signature: signer.sign(Id::hash(&payload)), payload}
    }

    pub fn verify(&self) -> Result<(), Error> {self.signature.verify(&self.key, Id::hash(&self.payload))}
}
impl<H: Hash + Debug + Clone> Clone for Signed<H> {
    fn clone(&self) -> Self {Signed{key: self.key, signature: self.signature, payload: self.payload.clone()}}
}
impl<H: Hash + Debug + Serialize> Serialize for Signed<H> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        (&self.key, &self.signature, &self.payload).serialize(serializer)
    }
}
impl<'de, H: Hash + Debug + Deserialize<'de>> Deserialize<'de> for Signed<H> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        <(PublicKey, Signature, H)>::deserialize(deserializer).map(|(key, signature, payload)| Signed{key, signature, payload})
    }
}
impl<H: Hash + Debug> AsRef<H> for Signed<H> {fn as_ref(&self) -> &H {&self.payload}}


#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Message([u8; 16], Vec<u8>);

pub struct Sink(FSChaCha20Poly1305);
impl Sink {
    pub fn encrypt(&mut self, mut data: Vec<u8>) -> Message {
        let tag = self.0.encrypt(&[], &mut data);
        Message(tag, data)
    }
}

pub struct Drain(FSChaCha20Poly1305);
impl Drain {
    pub fn decrypt(&mut self, mut message: Message) -> Result<Vec<u8>, Error> {
        self.0.decrypt(&[], &mut message.1, message.0).map_err(|_| Error::DecryptionFailed)?;
        Ok(message.1)
    }
}

//I can use the FsChaCha for length encryption like in BIP324 if needed
pub struct EncryptionStream(Sink, Drain);
impl EncryptionStream {
    pub fn new(recipient: &PublicKey) -> (Self, Init) {
        let key = SecretKey::new();
        let mine = ElligatorSwift::from_pubkey(key.public_key().0);
        let theirs = ElligatorSwift::from_pubkey(recipient.0);
        let ecdh_sk = ElligatorSwift::shared_secret(mine, theirs, key.0, Party::Initiator, Some(TAG.as_bytes()));
        let shared = SecretKey(secp256k1::SecretKey::from_byte_array(ecdh_sk.to_secret_bytes()).unwrap());

        let sender = FSChaCha20Poly1305::new(shared.derive(&[Id::MAX]).0.secret_bytes());
        let receiver = FSChaCha20Poly1305::new(shared.derive(&[Id::MIN]).0.secret_bytes());
        (Self(Sink(sender), Drain(receiver)), Init(mine))
    }

    pub fn receive(secret: &SecretKey, init: Init) -> Self {
        let mine = ElligatorSwift::from_pubkey(secret.public_key().0);
        let ecdh_sk = ElligatorSwift::shared_secret(init.0, mine, secret.0, Party::Responder, Some(TAG.as_bytes()));
        let shared = SecretKey(secp256k1::SecretKey::from_byte_array(ecdh_sk.to_secret_bytes()).unwrap());

        let receiver = FSChaCha20Poly1305::new(shared.derive(&[Id::MAX]).0.secret_bytes());
        let sender = FSChaCha20Poly1305::new(shared.derive(&[Id::MIN]).0.secret_bytes());
        Self(Sink(sender), Drain(receiver))
    }

    pub fn encrypt(&mut self, data: Vec<u8>) -> Message {
        self.0.encrypt(data)
    }

    pub fn decrypt(&mut self, message: Message) -> Result<Vec<u8>, Error> {
        self.1.decrypt(message)
    }
    
    pub fn split(self) -> (Sink, Drain) {(self.0, self.1)}
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
fn stream() {
    let remote = SecretKey::new();
    let rpub = remote.public_key();
    let (mut stream, init) = EncryptionStream::new(&rpub);

    let msg0 = b"hello".to_vec();
    let msg1 = b"I am trying to talk to you".to_vec();
    let msg2 = b"Sorry just saw these messages".to_vec();
    let msg3 = b"I also just don't want to talk to you...".to_vec();

    let mut receiver_stream = EncryptionStream::receive(&remote, init);

    let message0 = stream.encrypt(msg0.clone());
    let message1 = stream.encrypt(msg1.clone());
    assert_eq!(receiver_stream.decrypt(message0), Ok(msg0));
    assert_eq!(receiver_stream.decrypt(message1), Ok(msg1));

    let message2 = receiver_stream.encrypt(msg2.clone());
    assert_eq!(stream.decrypt(message2), Ok(msg2));

    let message3 = receiver_stream.encrypt(msg3.clone());
    assert_eq!(stream.decrypt(message3), Ok(msg3));
}
