use easy_secp256k1::{EasySecretKey, EasyPublicKey, EasyHash, Hashable};
use secp256k1::{SecretKey, PublicKey};
use serde::{Serialize, Deserialize};
use std::collections::{HashMap, BTreeMap};
use std::collections::hash_map::Entry;
use std::hash::{Hasher, Hash};
use std::ops::{DerefMut, Deref};
use std::cmp::Ordering;
use chrono::{DateTime, Utc};

use crate::did::{self, DidResolver, DidSecret, Did};
use crate::server::{Request, ChandlerRequest, ChandlerResponse, Error as PurserError};
use super::{requests, PrivateItem, ReadDMResult};

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum ValidationError {
    ///Action presence mismatched with protocol
    ActionMismatch(String),
    ///Action requires this secret key and it was not present
    MissingPerms(String),
    ///When combining permissions two different keys for the same action were found
    DifferentKeys(String),
    Deserialization(String),
    Decryption(String),
    MissingRecord(String),
    InvalidProtocol(Id),
    InvalidParent(String),
}
impl std::error::Error for ValidationError {}
impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {write!(f, "{:?}", self)}
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Error {
    MaliciousResponse(String),
    ConnectionFailed(String),
    Validation(ValidationError),
    SerdeJson(String),
    EasySecp256k1(String),
    Did(did::Error)
}
impl From<serde_json::Error> for Error {fn from(e: serde_json::Error) -> Error {Error::SerdeJson(format!("{:?}", e))}}
impl From<easy_secp256k1::Error> for Error {fn from(e: easy_secp256k1::Error) -> Error {Error::EasySecp256k1(format!("{:?}", e))}}
impl From<did::Error> for Error {fn from(error: did::Error) -> Self {Error::Did(error)}}
impl From<crate::server::Error> for Error {fn from(e: crate::server::Error) -> Error {match e {
    crate::server::Error::MaliciousResponse(response) => Error::MaliciousResponse(response),
    crate::server::Error::ConnectionFailed(error) => Error::ConnectionFailed(error),
}}}
impl From<ValidationError> for Error {fn from(e: ValidationError) -> Self {Error::Validation(e)}}
impl std::error::Error for Error {}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {write!(f, "{:?}", self)}
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Copy)]
pub struct Id([u8; 32]);
impl AsRef<[u8]> for Id {fn as_ref(&self) -> &[u8] {&self.0}}
impl Deref for Id {type Target = [u8; 32]; fn deref(&self) -> &Self::Target {&self.0}}
impl DerefMut for Id {fn deref_mut(&mut self) -> &mut Self::Target {&mut self.0}}
impl From<[u8; 32]> for Id {fn from(id: [u8; 32]) -> Self {Id(id)}}
impl Id {
    pub fn hash<H: Hash>(h: &H) -> Self {Id(*EasyHash::core_hash(h).as_ref())}
    pub fn random() -> Self {Id(rand::random())}
}
impl std::str::FromStr for Id {
    type Err = hex::FromHexError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Id(hex::decode(s)?.try_into().map_err(|_| hex::FromHexError::InvalidStringLength)?))
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub struct WSecretKey(pub SecretKey);
impl Deref for WSecretKey {type Target = SecretKey; fn deref(&self) -> &Self::Target {&self.0}}
impl DerefMut for WSecretKey {fn deref_mut(&mut self) -> &mut Self::Target {&mut self.0}}
impl Hash for WSecretKey {fn hash<H: Hasher>(&self, state: &mut H) {state.write(&self.secret_bytes())}}
impl From<SecretKey> for WSecretKey {fn from(key: SecretKey) -> WSecretKey {WSecretKey(key)}}
impl Ord for WSecretKey {fn cmp(&self, other: &Self) -> Ordering {self.secret_bytes().cmp(&other.secret_bytes())}}
impl PartialOrd for WSecretKey {fn partial_cmp(&self, other: &Self) -> Option<Ordering> {Some(self.cmp(other))}}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialOrd, Ord)]
pub enum Key {Secret(WSecretKey), Public(PublicKey)}
impl Hash for Key {fn hash<H: Hasher>(&self, state: &mut H) {self.public().hash(state);}}
impl PartialEq for Key {fn eq(&self, other: &Self) -> bool {self.public() == other.public()}}
impl Eq for Key {}
impl Key {
    pub fn public(&self) -> PublicKey {match self {
        Key::Secret(key) => key.easy_public_key(),
        Key::Public(key) => *key
    }}
    pub fn secret(&self) -> Option<WSecretKey> {match self {
        Key::Secret(key) => Some(*key),
        Key::Public(_) => None 
    }}
    pub fn set(self, secret: bool) -> Result<Self, ValidationError> {Ok(match secret {
        true => Key::Secret(self.secret().ok_or(ValidationError::MissingPerms("Secret".to_string()))?),
        false => self.to_public()
    })}
    pub fn max(self, other: Self) -> Result<Self, ValidationError> {
        match self != other {
            true => Err(ValidationError::DifferentKeys("?".to_string())),
            false => Ok(match &self {
                Key::Secret(_) => self,
                Key::Public(_) => match other {
                    Key::Secret(_) => other,
                    Key::Public(_) => self
                }
            })
        }
    }
    pub fn to_public(self) -> Self {Key::Public(self.public())}
}
pub type Keys = BTreeMap<String, Key>;

#[derive(Default, Debug, Clone, PartialEq, Eq, Hash, Ord, PartialOrd)]
#[derive(serde_with::SerializeDisplay)]
#[derive(serde_with::DeserializeFromStr)]
pub struct RecordPath(Vec<Id>);
impl RecordPath {
    pub fn root() -> Self {RecordPath(vec![])}
    pub fn parent(&self) -> Option<Self> {
        self.0.split_last().map(|t| RecordPath(t.1.to_vec()))
    }
    pub fn last(&self) -> Id {*self.0.last().unwrap_or(&Id::from([0; 32]))}
    pub fn is_root(&self) -> bool {self.0.is_empty()}
    pub fn join(&self, id: Id) -> Self {RecordPath([self.0.clone(), vec![id]].concat())}
}
impl Deref for RecordPath {type Target = Vec<Id>;fn deref(&self) -> &Self::Target {&self.0}}
impl std::fmt::Display for RecordPath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "/{}", self.0.iter().map(hex::encode).collect::<Vec<_>>().join("/"))
    }
}
impl std::str::FromStr for RecordPath {
    type Err = hex::FromHexError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(RecordPath(s.split("/").collect::<Vec<_>>().into_iter().flat_map(|id|
            (!id.is_empty()).then(|| Id::from_str(id))
        ).collect::<Result<Vec<Id>, hex::FromHexError>>()?))
    }
}

///Pathed key can be derived into two directions:
///1. Laterally by index to get children keys of this path
///2. Or Horizontally by adding to the path with new Ids
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct PathedKey(RecordPath, SecretKey);
impl AsRef<SecretKey> for PathedKey {fn as_ref(&self) -> &SecretKey {&self.1}}
impl PathedKey {
    pub fn new(path: RecordPath, key: SecretKey) -> Self {PathedKey(path, key)}
    fn path(&self) -> &RecordPath {&self.0}
    fn derive(&self, path: &RecordPath) -> Result<Self, ValidationError> {
        match path.to_string().strip_prefix(&self.0.to_string()) {
            Some(stripped) => Ok(PathedKey(path.clone(), self.1.easy_derive(&stripped.bytes().map(|b| b as u32).collect::<Vec<_>>()).unwrap())),
            None => Err(ValidationError::MissingPerms(path.to_string()))
        }
    }
    fn index(&self, index: u32) -> Result<SecretKey, Error> {
        Ok(self.1.easy_derive(&[u8::MAX as u32 + index])?)
    }
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Clone, Debug, Hash, Copy, PartialOrd, Ord)]
pub enum KeyState {Static(bool), Author(bool)}
impl KeyState {
    fn validate(&self, vkey: &Option<Key>, key: &Key, name: &str) -> Result<(), ValidationError> {
        match self {
            KeyState::Static(secret) => {
                if vkey.ok_or(ValidationError::ActionMismatch(format!("Validation Key, {}", name)))?.public() != key.public() {return Err(ValidationError::DifferentKeys(name.to_string()));}                
                if *secret && key.secret().is_none() {return Err(ValidationError::ActionMismatch(format!("Secret: {}", name)));}                
            },
            KeyState::Author(secret) => {
                if *secret != key.secret().is_some() {return Err(ValidationError::ActionMismatch(format!("Secret: {}", name)));}                
            }
        }
        Ok(())
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Hash)]
pub struct KeySet {
    pub discover: WSecretKey,//Always parent childern.0/index
    pub read: WSecretKey,//Always parent children.1/index
    pub children: Option<(Key, Key)>,
    pub others: BTreeMap<String, Key>
}
impl KeySet {
    pub fn delete(&self) -> Option<&Key> {self.others.get("delete")}
    pub fn max(mut self, other: Self) -> Result<Self, ValidationError> {
        let mut others = other.others.into_iter().map(|(n, k)|
            Ok((n.clone(), self.others.remove(&n).map(|k2| k.max(k2)).transpose()?.unwrap_or(k)))
        ).collect::<Result<BTreeMap<_, _>, ValidationError>>()?;
        others.extend(self.others);
        Ok(KeySet{
            discover: self.discover,
            read: self.read,
            children: self.children.map(|(d, r)| other.children.map(|(d2, r2)| Ok((d.max(d2)?, r.max(r2)?))).unwrap_or(Ok((d, r)))).transpose()?.or(other.children),
            others
        })
    }
}

//  #[derive(Serialize, Deserialize, PartialEq, Eq, Clone, Debug, Hash)]
//  pub struct SubKeySet<T> {
//      pub delete: Option<T>,
//      pub others: BTreeMap<String, T>
//  }
//  impl<T> Default for SubKeySet<T> {fn default() -> Self {SubKeySet{delete: None, others: BTreeMap::new()}}}
//  impl<T> SubKeySet<T> {pub fn new(delete: Option<T>, others: BTreeMap<String, T>) -> Self {SubKeySet{delete, others}}}
//  impl SubKeySet<KeyState> {
//      fn generic_id(&self) -> Id {
//          Id::hash(&(self.delete.map(|k| k.generic_id()), self.others.iter().map(|(s, k)| (s, k.generic_id())).collect::<Vec<_>>()))
//      }
//  }

type ValidationIds = (Id, Id, bool);//Hash, Generic, allow_generic
type ValidationListing = (Validation, bool);//allow_generic
#[derive(Serialize, Deserialize, PartialEq, Eq, Clone, Debug, Default, Hash)]
pub struct Validation {
    pub sub_validation: Option<(Vec<ValidationIds>, bool, bool, Option<bool>)>,
    //SubValidationIds, Anyone Discover, Anyone Read, Allow Pointers (deletable)
    pub key_validation: (BTreeMap<String, (Option<Key>, KeyState)>, bool)
}
impl Validation {
    pub fn generic_id(&self) -> Id {
        Id::hash(&(
            self.sub_validation.clone().map(|(ids, a, b, p)| {
                let mut ids = ids.iter().map(|(_, g, ag)| (*g, *ag)).collect::<Vec<_>>();
                ids.sort();
                (ids, a, b, p)
            }),
            self.key_validation.0.iter().map(|(n, (_, s))| (n, s)).collect::<Vec<_>>(),
            self.key_validation.1
        ))
    }
    pub fn new(sub_validation: Option<(Vec<ValidationListing>, bool, bool, Option<bool>)>, key_validation: (BTreeMap<String, (Option<Key>, KeyState)>, bool)) -> Self {
        let sub_validation = sub_validation.map(|(p,a,b,c)| (p.into_iter().map(|(p, ag)| (Id::hash(&p), p.generic_id(), ag)).collect::<Vec<_>>(), a, b, c));
        Validation{sub_validation, key_validation}
    }
    fn is_sub_validation(&self, validation: &Validation) -> bool {
        self.sub_validation.as_ref().map(|p|
            p.0.iter().any(|(p, g, ag)| *p == Id::hash(&validation) || (*ag && *g == validation.generic_id())) || p.0.is_empty()
        ).unwrap_or_default()
    }
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Clone, Debug, Hash)]
pub struct Header(KeySet, Validation, Vec<u8>);
impl Header {
    pub fn keys(&self) -> &KeySet {&self.0}
    pub fn generic_protocol_id(&self) -> Id {self.1.generic_id()}
    pub fn data(&self) -> &Vec<u8> {&self.2}
    fn validate(&self) -> Result<(), ValidationError> {
        if self.1.sub_validation.is_some() != self.0.children.is_some() {return Err(ValidationError::ActionMismatch("Children".to_string()));}
        self.1.sub_validation.as_ref().map(|(_, d, r, _)| {
            let children = self.0.children.unwrap();
            if children.0.secret().is_some() != *d {return Err(ValidationError::ActionMismatch("DiscoverChild".to_string()));}
            if children.1.secret().is_some() != *r {return Err(ValidationError::ActionMismatch("ReadChild".to_string()));}
            Ok(())
        }).transpose()?;
        if !self.1.key_validation.1 {
            for n in self.0.others.keys() {
                if !self.1.key_validation.0.contains_key(n) {
                    return Err(ValidationError::ActionMismatch(format!("Extra Key {}", n)));
                }
            }
        }
        for (n, (vk, ks)) in &self.1.key_validation.0 {
            let ok = self.0.others.get(n).ok_or(ValidationError::ActionMismatch(format!("Missing Key {}", n)))?;
            ks.validate(vk, ok, n)?;
        }
        Ok(())
    }

    fn validate_child(&self, child: &Self) -> Result<(), ValidationError> {
        if self.1.is_sub_validation(&child.1) {return Ok(());}
        Err(ValidationError::InvalidProtocol(Id::hash(&child.1)))
    }

    fn max(self, other: Self) -> Result<Self, ValidationError> {
        Ok(Header(self.0.max(other.0)?, self.1, self.2)) 
    }
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Clone, Debug, Hash)]
pub struct Record {
    pub header: Header,
    pub payload: Vec<u8>
}
impl Record {
    fn from_item(item: PrivateItem, read: SecretKey) -> Result<Record, ValidationError> {
        let record: Record = serde_json::from_slice(
            &read.easy_decrypt(&item.payload).map_err(|e| ValidationError::Decryption(e.to_string()))?
        ).map_err(|e| ValidationError::Deserialization(e.to_string()))?;
        if record.header.0.discover.easy_public_key() != item.discover {return Err(ValidationError::DifferentKeys("Discover".to_string()));}
        if *record.header.0.read != read {return Err(ValidationError::DifferentKeys("Read".to_string()));}
        if record.header.0.delete().map(|d| d.public()) != item.delete {return Err(ValidationError::DifferentKeys("ItemDelete".to_string()));}
        record.header.validate()?;
        Ok(record)
    }
}

pub trait Protocol {
    fn generate(&self, cache: &mut Cache, parent: &RecordPath, record_key: &SecretKey, index: u32) -> Result<(Keys, Validation, Vec<u8>), ValidationError>;
}

#[derive(Clone, Debug)]
struct Pointer(Header, bool);
impl Protocol for Pointer {
    fn generate(
        &self, _cache: &mut Cache, _parent: &RecordPath, _record_key: &SecretKey, _index: u32
    ) -> Result<(BTreeMap<String, Key>, Validation, Vec<u8>), ValidationError> {
        Ok((BTreeMap::default(), Validation::new(
            None, (BTreeMap::default(), false)
        ), serde_json::to_vec(&self.0).unwrap()))
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Cache(PathedKey, HashMap<RecordPath, (Header, u32)>);
impl Cache {
    pub fn new(root: PathedKey) -> Self {
        let header = Header(
            KeySet {
                discover: WSecretKey(SecretKey::easy_new()),
                read: WSecretKey(SecretKey::easy_new()),
                children: Some((Key::Secret(root.as_ref().easy_derive(&[0]).unwrap().into()), Key::Secret(root.as_ref().easy_derive(&[1]).unwrap().into()))),
                others: BTreeMap::default()
            },
            Validation::new(Some((vec![], true, true, Some(true))), (BTreeMap::default(), false)),
            vec![]
        );
        let path = root.path().clone();
        Cache(root, HashMap::from([(path, (header, 0))]))
    }

    pub fn cache(&mut self, parent: RecordPath, header: Header, index: u32) {
        match self.1.entry(parent.join(Id::hash(&header))) {
            Entry::Vacant(entry) => {entry.insert((header, index));},
            Entry::Occupied(mut entry) => {
                let value = entry.get_mut();
                value.0 = header.max(value.0.clone()).unwrap();
                value.1 = index.max(value.1);
            }
        }
    }

    pub fn cache_index(&mut self, path: &RecordPath, index: u32) -> u32 {
        self.1.get_mut(path).map(|(_, latest)| {*latest = index.max(*latest); *latest}).unwrap_or_default()
    }

    

    pub fn get_index(&self, path: &RecordPath) -> u32 {
        self.1.get(path).map(|(_, index)| *index).unwrap_or_default()
    }

    fn get(&self, path: &RecordPath) -> Option<(&Header, u32)> {
        self.1.get(path).map(|(header, index)| (header, *index))
    }
    fn header(&mut self, parent: &RecordPath, protocol: impl Protocol, index: u32) -> Result<Header, Error> {
        let mkey = self.0.derive(parent)?.index(index)?;
        let discover_child = mkey.easy_derive(&[0])?;
        let read_child = mkey.easy_derive(&[1])?;
        let record_key = mkey.easy_derive(&[2])?;
        let (subset, validation, data) = protocol.generate(self, parent, &record_key, index)?;
        let (parent_h, _) = self.get(parent).ok_or(ValidationError::MissingRecord(parent.to_string()))?;
        if !parent_h.1.is_sub_validation(&validation) {return Err(ValidationError::InvalidProtocol(Id::hash(&validation)).into());}
        let children = parent_h.0.children.ok_or(ValidationError::InvalidParent(parent.to_string()))?;
        let discover = children.0.secret().ok_or(ValidationError::MissingPerms("DiscoverChild".to_string()))?.easy_derive(&[index])?;
        let read = children.1.secret().ok_or(ValidationError::MissingPerms("ReadChild".to_string()))?.easy_derive(&[index])?;
        let header = Header(
            KeySet{
                discover: WSecretKey(discover),
                read: WSecretKey(read),
                children: validation.sub_validation.as_ref().map(|(_, d, r, _)| (
                    Key::Secret(discover_child.into()).set(*d).unwrap(),
                    Key::Secret(read_child.into()).set(*r).unwrap())
                ),
                others: subset
            },
            validation,
            data
        );
        header.validate()?;
        Ok(header)
    }
}
impl std::fmt::Debug for Cache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.1.keys().map(|p| p.to_string()).collect::<Vec<_>>())
    }
}

#[derive(Clone, Debug, Hash)]
pub struct Discover(requests::ReadPrivate, Option<WSecretKey>, Header, RecordPath, u32);
impl AsRef<ChandlerRequest> for Discover {fn as_ref(&self) -> &ChandlerRequest {self.0.as_ref()}}
impl Discover {
    pub fn new(cache: &mut Cache, parent: &RecordPath, index: u32) -> Result<Self, Error> {
        let (header, _) = cache.get(parent).ok_or(ValidationError::MissingRecord(parent.to_string()))?;
        let children = header.0.children.and_then(|(d, r)| d.secret().map(|d| (d, r))).ok_or(ValidationError::InvalidParent(parent.to_string()))?;
        let discover = children.0.easy_derive(&[index])?;
        Ok(Discover(requests::ReadPrivate::new(&discover), children.1.secret(), header.clone(), parent.clone(), index))
    }
}
impl Request for Discover {
    type Output = Result<Option<Option<DiscoverResult>>, Error>;
    fn process(self, response: Result<ChandlerResponse, PurserError>) -> Self::Output {
        let read = self.1.map(|r| r.easy_derive(&[self.4]).unwrap());
        Ok(self.0.process(response)?.map(|item| read.and_then(|r| Record::from_item(item, r).ok()).map(|record| {
            DiscoverResult(record, self.2, self.3, self.4)
        })))
    }
}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct DiscoverResult(Record, Header, RecordPath, u32);
impl DiscoverResult {
    pub fn protocol_id(&self) -> Id {self.0.header.1.generic_id()}
    pub fn process(self, cache: &mut Cache, protocol: impl Protocol) -> Result<Option<RecordPath>, Error> {
        if self.1.validate_child(&self.0.header).is_err() {return Ok(None);}
        //if Id::hash(&self.0.header.1) == Pointer::id() {todo!()}
        let header = cache.header(&self.2, protocol, self.3)?;
        let id = Id::hash(&self.0.header);
        if Id::hash(&header) == id {
            println!("As author");
            cache.cache(self.2.clone(), header, 0);
        } else {
            println!("Not as author");
            cache.cache(self.2.clone(), self.0.header, 0);
        }
        Ok(Some(self.2.join(id)))
    }
}

#[derive(Clone, Debug, Hash)]
pub struct Create(requests::CreatePrivate, Record, RecordPath);
impl AsRef<ChandlerRequest> for Create {fn as_ref(&self) -> &ChandlerRequest {self.0.as_ref()}}
impl Create {
    pub fn new(cache: &mut Cache, parent: &RecordPath, protocol: impl Protocol, index: u32, payload: Vec<u8>) -> Result<Self, Error> {
        let header = cache.header(parent, protocol, index)?;
        cache.cache(parent.clone(), header.clone(), 0);
        let record = Record{header: header.clone(), payload};
        let discover = &record.header.0.discover;
        let delete = record.header.0.delete().map(|d| d.public());
        let payload = record.header.0.read.easy_public_key().easy_encrypt(serde_json::to_vec(&record)?)?;
        Ok(Create(requests::CreatePrivate::new(discover, delete, payload), record, parent.join(Id::hash(&header))))
    }
}
impl Request for Create {
    type Output = Result<(RecordPath, Option<Result<Record, ValidationError>>), Error>;

    fn process(self, response: Result<ChandlerResponse, PurserError>) -> Self::Output {
        Ok((self.2, self.0.process(response)?.and_then(|item| match Record::from_item(item, *self.1.header.0.read) {
            Ok(record) => (record != self.1).then_some(Ok(record)),
            res => Some(res)
        })))
    }
}

#[derive(Clone, Debug, Hash)]
pub struct Read(requests::ReadPrivate, WSecretKey, Id);
impl AsRef<ChandlerRequest> for Read {fn as_ref(&self) -> &ChandlerRequest {self.0.as_ref()}}
impl Read {
    pub fn new(cache: &mut Cache, path: &RecordPath) -> Result<Self, ValidationError> {
        let (header, _) = cache.get(path).ok_or(ValidationError::MissingRecord(path.to_string()))?;
        Ok(Read(requests::ReadPrivate::new(&header.0.discover), header.0.read, Id::hash(&header)))
    }
}
impl Request for Read {
    type Output = Result<Option<Record>, Error>;
    fn process(self, response: Result<ChandlerResponse, PurserError>) -> Self::Output {
        Ok(self.0.process(response)?.and_then(|item| Record::from_item(item, *self.1).ok().filter(|r| Id::hash(&r.header) == self.2)))
    }
}

#[derive(Clone, Debug, Hash)]
pub struct Share(requests::CreateDM);
impl AsRef<ChandlerRequest> for Share {fn as_ref(&self) -> &ChandlerRequest {self.0.as_ref()}}
impl Share {
    pub async fn new(cache: &mut Cache, resolver: &mut dyn DidResolver, secret: impl DidSecret, recipient: Did, path: &RecordPath) -> Result<Self, Error> {
        let (header, _) = cache.get(path).ok_or(ValidationError::MissingRecord(path.to_string()))?;
        Ok(Share(requests::CreateDM::new(resolver, secret, recipient, serde_json::to_vec(&header)?).await?))
    }
}
impl Request for Share {
    type Output = Result<(), Error>;
    fn process(self, response: Result<ChandlerResponse, PurserError>) -> Self::Output {
        Ok(self.0.process(response)?)
    }
}

#[derive(Clone)]
pub struct Receive(requests::ReadDM);
impl AsRef<ChandlerRequest> for Receive {fn as_ref(&self) -> &ChandlerRequest {self.0.as_ref()}}
impl Receive {
    pub async fn new(resolver: &mut dyn DidResolver, secret: impl DidSecret, since: DateTime::<Utc>) -> Result<Self, Error> {
        Ok(Receive(requests::ReadDM::new(resolver, secret, since.timestamp()).await?))
    }
}
impl Request for Receive {
    type Output = Result<ReceiveResult, Error>;
    fn process(self, response: Result<ChandlerResponse, PurserError>) -> Self::Output {
        Ok(ReceiveResult(self.0.process(response)?))
    }
}
pub struct ReceiveResult(ReadDMResult);
impl ReceiveResult {
    pub async fn process(self, cache: &mut Cache, resolver: &mut dyn DidResolver) -> Result<Vec<(Did, RecordPath)>, Error> {
        let sent = self.0.process(resolver).await?;
        Ok(sent.into_iter().flat_map(|(s, p)| {
            let header = serde_json::from_slice::<Header>(&p).ok()?;
            header.validate().ok()?;
            let id = Id::hash(&header);
            let parent = RecordPath(vec![Id([u8::MAX; 32])]);
            let path = parent.join(id);
            cache.cache(parent, header, 0);
            Some((s, path))
        }).collect())
    }
}

//  #[derive(Clone, Debug, Hash)]
//  pub struct CreatePointer(requests::CreatePrivate, Record, RecordPath);
//  impl AsRef<ChandlerRequest> for CreatePointer {fn as_ref(&self) -> &ChandlerRequest {self.0.as_ref()}}
//  impl CreatePointer {
//      pub fn new(cache: &mut Cache, parent: &RecordPath, record: &RecordPath, delete: bool) -> Result<Self, Error> {
//          let header = cache.header(parent, protocol, index)?;
//          cache.cache(parent.clone(), header.clone(), 0);
//          let record = Record{header: header.clone(), payload};
//          let discover = &record.header.0.discover;
//          let delete = record.header.0.delete.map(|d| d.public());
//          let payload = record.header.0.read.easy_public_key().easy_encrypt(serde_json::to_vec(&record)?)?;
//          Ok(Create(requests::CreatePrivate::new(discover, delete, payload), record, parent.join(Id::hash(&header))))
//      }
//  }
//  impl Request for CreatePointer {
//      type Output = Result<RecordPath, Error>;

//      fn process(self, response: Result<ChandlerResponse, PurserError>) -> Self::Output {
//          Ok((self.2, self.0.process(response)?.and_then(|item| match Record::from_item(item, *self.1.header.0.read) {
//              Ok(record) => (record != self.1).then_some(Ok(record)),
//              res => Some(res)
//          })))
//      }
//  }

//  #[derive(Clone, Debug, Hash)]
//  pub struct Update(requests::UpdatePrivate);
//  impl AsRef<ChandlerRequest> for Update {fn as_ref(&self) -> &ChandlerRequest {self.0.as_ref()}}
//  impl Update {
//      pub fn new(record: &Record, header: &Header) -> Result<Self, ValidationError> {
//          let discover = &record.header.0.discover;
//          let delete = header.0.delete.and_then(|d| d.secret()).ok_or(ValidationError::MissingPerms("Delete".to_string()))?;
//          let payload = record.header.0.read.easy_public_key().easy_encrypt(serde_json::to_vec(&record)?)?;
//          Ok(Update(requests::UpdatePrivate::new(discover, &delete, payload)))
//      }
//  }
//  impl RequestTrait for Update {
//      type Output = Result<bool, Error>;
//      fn process(self, response: Result<ChandlerResponse, Error>) -> Self::Output {
//          Ok(self.0.process(response)?.is_none())
//      }
//  }

//  #[derive(Clone, Debug, Hash)]
//  pub struct Delete(requests::DeletePrivate);
//  impl AsRef<ChandlerRequest> for Delete {fn as_ref(&self) -> &ChandlerRequest {self.0.as_ref()}}
//  impl Delete {
//      pub fn new(header: &Header) -> Result<Self, ValidationError> {
//          let delete = header.0.delete.and_then(|d| d.secret()).ok_or(ValidationError::MissingPerms("Delete".to_string()))?;
//          Ok(Delete(requests::DeletePrivate::new(header.0.discover.easy_public_key(), &delete)))

//      }
//  }
//  impl RequestTrait for Delete {
//      type Output = Result<bool, Error>;
//      fn process(self, response: Result<ChandlerResponse, Error>) -> Self::Output {
//          Ok(self.0.process(response)?.is_none())
//      }
//  }
