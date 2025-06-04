use easy_secp256k1::{EasySecretKey, EasyPublicKey};
use secp256k1::{SecretKey, PublicKey};
use serde::{Serialize, Deserialize};
use std::collections::{HashMap, BTreeMap};
use std::hash::{Hasher, Hash};
use std::ops::{DerefMut, Deref};
use std::cmp::Ordering;
use std::fmt::Debug;

use crate::{DateTime, Id};
use crate::orange_name::{self, OrangeResolver, OrangeSecret, OrangeName};
use crate::server::{Request, Response};
use super::PrivateItem;

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
    CriticalOrange(String)
}
impl Error {pub(crate) fn mr(e: impl Debug) -> Self {Error::MaliciousResponse(format!("{:?}", e))}}
impl From<serde_json::Error> for Error {fn from(e: serde_json::Error) -> Error {Error::SerdeJson(format!("{:?}", e))}}
impl From<easy_secp256k1::Error> for Error {fn from(e: easy_secp256k1::Error) -> Error {Error::EasySecp256k1(format!("{:?}", e))}}
impl From<orange_name::Error> for Error {fn from(error: orange_name::Error) -> Self {match error{
    orange_name::Error::Critical(error) => {Error::CriticalOrange(error)}
    resolution => Error::ConnectionFailed(format!("{:?}", resolution)),
}}}
impl From<crate::server::Error> for Error {fn from(e: crate::server::Error) -> Error {match e {
    crate::server::Error::MaliciousResponse(response) => Error::MaliciousResponse(response),
    crate::server::Error::ConnectionFailed(error) => Error::ConnectionFailed(error),
    crate::server::Error::CriticalOrange(error) => Error::CriticalOrange(error),
}}}
impl From<ValidationError> for Error {fn from(e: ValidationError) -> Self {Error::Validation(e)}}
impl std::error::Error for Error {}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {write!(f, "{:?}", self)}
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
pub struct WSecretKey(pub SecretKey);
impl Deref for WSecretKey {type Target = SecretKey; fn deref(&self) -> &Self::Target {&self.0}}
impl DerefMut for WSecretKey {fn deref_mut(&mut self) -> &mut Self::Target {&mut self.0}}
impl Hash for WSecretKey {fn hash<H: Hasher>(&self, state: &mut H) {state.write(&self.secret_bytes())}}
impl From<SecretKey> for WSecretKey {fn from(key: SecretKey) -> WSecretKey {WSecretKey(key)}}
impl Ord for WSecretKey {fn cmp(&self, other: &Self) -> Ordering {self.secret_bytes().cmp(&other.secret_bytes())}}
impl PartialOrd for WSecretKey {fn partial_cmp(&self, other: &Self) -> Option<Ordering> {Some(self.cmp(other))}}
impl std::fmt::Debug for WSecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:.10} D> {:.10}", hex::encode(self.secret_bytes()), self.easy_public_key().to_string())
    }
}

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

#[derive(Serialize, Deserialize, PartialEq, Eq, Clone, Debug, Default, Hash)]
pub struct Permissions {
    pub children: Option<(bool, bool)>,
    pub delete: Option<bool>,
    pub keys: BTreeMap<String, bool>,
}
impl Permissions {
    pub fn new(children: Option<(bool, bool)>, delete: Option<bool>, keys: BTreeMap<String, bool>) -> Self {
        Permissions{children, delete, keys}
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Hash)]
pub struct KeySet {
    pub discover: WSecretKey,//Always parent childern.0/index
    pub read: WSecretKey,//Always parent children.1/index
    pub children: Option<(Key, Key)>,
    pub delete: Option<Key>,
    pub others: BTreeMap<String, Key>
}
impl KeySet {
    pub fn max(mut self, other: Self) -> Result<Self, ValidationError> {
        let mut others = other.others.into_iter().map(|(n, k)|
            Ok((n.clone(), self.others.remove(&n).map(|k2| k.max(k2)).transpose()?.unwrap_or(k)))
        ).collect::<Result<BTreeMap<_, _>, ValidationError>>()?;
        others.extend(self.others);
        Ok(KeySet{
            discover: self.discover,
            read: self.read,
            delete: self.delete.map(|d| other.delete.map(|d2| d.max(d2)).unwrap_or(Ok(d))).transpose()?.or(other.delete),
            children: self.children.map(|(d, r)| other.children.map(|(d2, r2)| Ok((d.max(d2)?, r.max(r2)?))).unwrap_or(Ok((d, r)))).transpose()?.or(other.children),
            others
        })
    }

    pub fn set(self, perms: &Permissions) -> Result<Self, ValidationError> {
        Ok(KeySet{
            discover: self.discover,
            read: self.read,
            delete: match (self.delete, perms.delete) {
                (Some(d), Some(p)) => Some(d.set(p)?),
                (None, None) => None,
                _ => {return Err(ValidationError::ActionMismatch("Delete".to_string()));}
            },
            children: perms.children.map(|pc| {
                let children = self.children.ok_or(ValidationError::ActionMismatch("Children".to_string()))?;
                Ok((children.0.set(pc.0)?, children.1.set(pc.1)?))
            }).transpose()?,
            others: self.others.into_iter().map(|(n, k)| Ok((n.clone(), perms.keys.get(&n).map(|s| k.set(*s)).transpose()?.unwrap_or(k)))).collect::<Result<BTreeMap<_,_>, ValidationError>>()?
        })
    }
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Clone, Debug, Default, Hash)]
pub struct ChildrenValidation {
    pub children: Vec<Id>,
    pub anyone_discover: bool,
    pub anyone_read: bool,
    pub allow_pointers: bool,
}
impl ChildrenValidation {
    pub fn new(children: Vec<Id>, anyone_discover: bool, anyone_read: bool, allow_pointers: bool) -> Self {
        ChildrenValidation{children, anyone_discover, anyone_read, allow_pointers}
    }
}
 
#[derive(Serialize, Deserialize, PartialEq, Eq, Clone, Debug, Default, Hash)]
pub struct Validation {
    pub children: Option<ChildrenValidation>,
    pub delete: Option<bool>,
    pub key_states: BTreeMap<String, bool>,
    pub allow_extra_keys: bool
}
impl Validation {
    pub fn new(children: Option<ChildrenValidation>, delete: Option<bool>, key_states: BTreeMap<String, bool>, allow_extra_keys: bool) -> Self {
        Validation{children, delete, key_states, allow_extra_keys}
    }
    pub fn id(&self) -> Id {Id::hash(&self)}
    fn validate(&self, keyset: &KeySet) -> Result<(), ValidationError> {
        if self.children.is_some() != self.children.is_some() {return Err(ValidationError::ActionMismatch("Children".to_string()));}
        self.children.as_ref().map(|cv| {
            let children = keyset.children.ok_or(ValidationError::ActionMismatch("Children".to_string()))?;
            if cv.anyone_discover && children.0.secret().is_none() {return Err(ValidationError::ActionMismatch("DiscoverChild".to_string()));}
            if cv.anyone_read && children.1.secret().is_none() {return Err(ValidationError::ActionMismatch("ReadChild".to_string()));}
            Ok(())
        }).transpose()?;
        self.delete.as_ref().map(|d| {
            let key_delete = keyset.delete.ok_or(ValidationError::ActionMismatch("Delete".to_string()))?;
            if *d && key_delete.secret().is_none() {return Err(ValidationError::MissingPerms("Delete".to_string()));}
            Ok(())
        }).transpose()?;
        if !self.allow_extra_keys && (keyset.others.keys().collect::<Vec<_>>() != self.key_states.keys().collect::<Vec<_>>()) {
            return Err(ValidationError::ActionMismatch("Extra Keys".to_string()));
        }
        for (n, secret) in &self.key_states {
            let ok = keyset.others.get(n).ok_or(ValidationError::ActionMismatch(format!("Missing Key {}", n)))?;
            if *secret && ok.secret().is_none() {return Err(ValidationError::MissingPerms(n.to_string()));}                
        }
        Ok(())
    }
    fn is_child(&self, id: &Id) -> bool {
        self.children.as_ref().map(|c| c.children.contains(id) || c.children.is_empty()).unwrap_or_default()
    }
    fn pointer(&self) -> bool {
        self.children.as_ref().map(|c| c.allow_pointers).unwrap_or_default()
    }
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Clone, Debug, Hash)]
pub struct Header(KeySet, Validation, Vec<u8>, Id);
impl Header {
    pub fn keys(&self) -> &KeySet {&self.0}
    pub fn validation_id(&self) -> Id {self.1.id()}
    pub fn protocol_id(&self) -> Id {self.3}
    pub fn id(&self) -> Id {Id::hash(&self)}
    pub fn data(&self) -> &Vec<u8> {&self.2}

    fn validate(&self) -> Result<(), ValidationError> {self.1.validate(&self.0)}
    fn validate_child(&self, child: &Self) -> Result<(), ValidationError> {
        if child.3 != Id::MAX && self.1.is_child(&child.3) {return Ok(());}
        if self.1.pointer() && child.3 == Id::MAX {return Ok(());}
        Err(ValidationError::InvalidProtocol(self.3))
    }

    fn max(self, other: Self) -> Result<Self, ValidationError> {
        Ok(Header(self.0.max(other.0)?, self.1, self.2, self.3)) 
    }

    fn set(mut self, perms: &Permissions) -> Result<Self, ValidationError> {
        self.0 = self.0.set(perms)?;
        self.validate()?;
        Ok(self)
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
        if record.header.0.delete.map(|d| d.public()) != item.delete {return Err(ValidationError::DifferentKeys("ItemDelete".to_string()));}
        record.header.validate()?;
        Ok(record)
    }
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Clone, Debug, Hash)]
pub struct HeaderInfo{
    delete: Option<Key>,
    others: Keys,
    data: Vec<u8>
}
impl HeaderInfo {pub fn new(delete: Option<Key>, others: Keys, data: Vec<u8>) -> Self {HeaderInfo{delete, others, data}}}

pub trait Protocol: Debug {
    fn validation(&self) -> Validation;
    fn header_info(&self, cache: &mut Cache, parent: &RecordPath, record_key: &SecretKey, index: u32) -> Result<HeaderInfo, ValidationError>;
    fn id(&self) -> Id {self.validation().id()}
}

#[derive(Clone, Debug)]
struct Pointer(Header);
impl Protocol for Pointer {
    fn validation(&self) -> Validation {Validation::new(None, None, BTreeMap::new(), false)}
    fn header_info(&self,
        _cache: &mut Cache, _parent: &RecordPath, _record_key: &SecretKey, _index: u32
    ) -> Result<HeaderInfo, ValidationError> {
        Ok(HeaderInfo::new(None, BTreeMap::new(), serde_json::to_vec(&self.0).unwrap()))
    }
    fn id(&self) -> Id {Id::MAX}
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Cache(PathedKey, HashMap<RecordPath, Header>);
impl Cache {
    pub fn new(root: PathedKey) -> Self {
        let validation = Validation::new(Some(ChildrenValidation::new(vec![], true, true, true)), None, BTreeMap::default(), false);
        let validation_id = validation.id();
        let header = Header(
            KeySet {
                discover: WSecretKey(SecretKey::easy_new()),
                read: WSecretKey(SecretKey::easy_new()),
                children: Some((Key::Secret(root.as_ref().easy_derive(&[0]).unwrap().into()), Key::Secret(root.as_ref().easy_derive(&[1]).unwrap().into()))),
                delete: None,
                others: BTreeMap::default()
            }, validation, vec![], validation_id
        );
        let path = root.path().clone();
        Cache(root, HashMap::from([(path, header)]))
    }

    pub fn get(&self, path: &RecordPath) -> Option<&Header> {self.1.iter().find_map(|(k, v)| k.to_string().strip_suffix(&path.to_string()).map(|_| v))}
    pub fn remove(&mut self, path: &RecordPath) -> Option<Header> {self.1.remove(path)}

    fn cache(&mut self, parent: RecordPath, mut header: Header) {
        self.1.iter_mut().for_each(|(k, v)| {if k.to_string().strip_suffix(&RecordPath(vec![header.id()]).to_string()).is_some() {
            header = header.clone().max(v.clone()).unwrap();
            *v = header.clone();
        }});
        self.1.insert(parent.join(header.id()), header);
    }

    fn header(&mut self, parent: &RecordPath, protocol: &dyn Protocol, index: u32) -> Result<Header, Error> {
        let mkey = self.0.derive(parent)?.index(index)?;
        let discover_child = mkey.easy_derive(&[0])?;
        let read_child = mkey.easy_derive(&[1])?;
        let record_key = mkey.easy_derive(&[2])?;
        let header_info = protocol.header_info(self, parent, &record_key, index)?;
        let validation = protocol.validation();
        let parent_h = self.get(parent).ok_or(ValidationError::MissingRecord(parent.to_string()))?;
        if !parent_h.1.is_child(&protocol.id()) {return Err(ValidationError::InvalidProtocol(protocol.id()).into());}
        let children = parent_h.0.children.ok_or(ValidationError::InvalidParent(parent.to_string()))?;
        let discover = children.0.secret().ok_or(ValidationError::MissingPerms("DiscoverChild".to_string()))?.easy_derive(&[index])?;
        let read = children.1.secret().ok_or(ValidationError::MissingPerms("ReadChild".to_string()))?.easy_derive(&[index])?;
        let header = Header(
            KeySet{
                discover: WSecretKey(discover),
                read: WSecretKey(read),
                children: validation.children.as_ref().map(|_| (
                    Key::Secret(discover_child.into()),
                    Key::Secret(read_child.into())
                )),
                delete: header_info.delete,
                others: header_info.others,
            },
            validation,
            header_info.data,
            protocol.id()
        );
        header.validate()?;
        Ok(header)
    }
}
impl std::fmt::Debug for Cache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_map().entries(self.1.iter().map(|(p, h)| (p.to_string(), &h.0))).finish()
    }
}

#[derive(Debug)]
enum MidState {
    Discover(Option<SecretKey>, Header, RecordPath, u32, Vec<Box<dyn Protocol>>),
    Create(Record, RecordPath),
    Read(SecretKey, Id),
    Update,
    Delete,
    Share,
    Receive,
}

pub enum Processed {
    Discover(Option<(RecordPath, DateTime)>),
    Create(RecordPath, Option<(Result<Record, ValidationError>, DateTime)>),
    Read(Option<(Record, DateTime)>),
    Update(bool),
    Delete(bool),
    Share,
    Receive(Vec<(OrangeName, RecordPath)>),
}

pub struct Client(super::Client, MidState);
impl Client {
    pub fn discover(cache: &mut Cache, parent: &RecordPath, index: u32, protocols: Vec<Box<dyn Protocol>>) -> Result<Self, Error> { 
        let header = cache.get(parent).ok_or(ValidationError::MissingRecord(parent.to_string()))?;
        let children = header.0.children.and_then(|(d, r)| d.secret().map(|d| (d, r))).ok_or(ValidationError::InvalidParent(parent.to_string()))?;
        let discover = children.0.easy_derive(&[index])?;
        let read = children.1.secret().map(|r| r.easy_derive(&[index]).unwrap());
        Ok(Client(super::Client::read_private(&discover), MidState::Discover(read, header.clone(), parent.clone(), index, protocols)))
    }

    pub fn create(cache: &mut Cache, parent: &RecordPath, protocol: &dyn Protocol, index: u32, perms: &Permissions, payload: Vec<u8>) -> Result<Self, Error> {
        let o_header = cache.header(parent, protocol, index)?;
        let header = o_header.clone().set(perms)?;
        cache.cache(parent.clone(), o_header);
        let record = Record{header, payload};
        let discover = &record.header.0.discover;
        let delete = record.header.0.delete.map(|d| d.public());
        let payload = record.header.0.read.easy_public_key().easy_encrypt(serde_json::to_vec(&record)?)?;
        let path = parent.join(record.header.id());
        Ok(Client(super::Client::create_private(discover, delete, payload), MidState::Create(record, path)))
    }

    pub fn read(cache: &mut Cache, path: &RecordPath) -> Result<Self, Error> {
        let header = cache.get(path).ok_or(ValidationError::MissingRecord(path.to_string()))?;
        Ok(Client(super::Client::read_private(&header.0.discover), MidState::Read(*header.0.read, Id::hash(&header))))
    }

    pub fn update(cache: &mut Cache, path: &RecordPath, perms: &Permissions, payload: Vec<u8>) -> Result<Self, Error> {
        let header = cache.get(path).ok_or(ValidationError::MissingRecord(path.to_string()))?.clone();
        let delete = header.0.delete.and_then(|d| d.secret()).ok_or(ValidationError::MissingPerms("Delete".to_string()))?;
        let header = header.set(perms)?;
        let record = Record{header, payload};
        let discover = &record.header.0.discover;
        let payload = record.header.0.read.easy_public_key().easy_encrypt(serde_json::to_vec(&record)?)?;
        Ok(Client(super::Client::update_private(discover, &delete, payload), MidState::Update))
    }

    pub fn delete(cache: &mut Cache, path: &RecordPath) -> Result<Self, Error> {
        let header = cache.get(path).ok_or(ValidationError::MissingRecord(path.to_string()))?;
        let discover = header.0.discover.easy_public_key();
        let delete = header.0.delete.and_then(|d| d.secret()).ok_or(ValidationError::MissingPerms("Delete".to_string()))?;
        Ok(Client(super::Client::delete_private(discover, &delete), MidState::Delete))
    }

    pub async fn share(cache: &mut Cache, resolver: &mut OrangeResolver, secret: &OrangeSecret, recipient: &OrangeName, perms: &Permissions, path: &RecordPath) -> Result<Self, Error> {
        let header = cache.get(path).ok_or(ValidationError::MissingRecord(path.to_string()))?;
        let header = header.clone().set(perms)?;
        Ok(Client(super::Client::create_dm(resolver, secret, recipient.clone(), serde_json::to_vec(&header)?).await?, MidState::Share))
    }

    pub async fn receive(resolver: &mut OrangeResolver, secret: &OrangeSecret, since: DateTime) -> Result<Self, Error> {
        Ok(Client(super::Client::read_dm(resolver, secret, since).await?, MidState::Receive))
    }

    pub fn create_pointer(cache: &mut Cache, parent: &RecordPath, record: &RecordPath, index: u32) -> Result<Self, Error> {
        let record_header = cache.get(record).ok_or(ValidationError::MissingRecord(record.to_string()))?.clone();
        cache.cache(parent.clone(), record_header.clone());
        let protocol = Pointer(record_header);
        let header = cache.header(parent, &protocol, index)?;
        let record = Record{header: header.clone(), payload: vec![]};
        let discover = &record.header.0.discover;
        let delete = record.header.0.delete.map(|d| d.public());
        let payload = record.header.0.read.easy_public_key().easy_encrypt(serde_json::to_vec(&record)?)?;
        Ok(Client(super::Client::create_private(discover, delete, payload), MidState::Create(record, parent.join(Id::hash(&header)))))
    }

    pub fn build_request(&self) -> Request {self.0.build_request()}

    pub async fn process_response(&self, cache: &mut Cache, resolver: &mut OrangeResolver, response: Response) -> Result<Processed, Error> {
        Ok(match (&self.1, self.0.process_response(resolver, response).await?) {
            (MidState::Discover(_,_,_,_,_), super::Processed::PrivateItem(None)) | (MidState::Discover(None,_,_,_,_), super::Processed::PrivateItem(_)) => Processed::Discover(None),
            (MidState::Discover(Some(read), parent_header, parent, index, protocols), super::Processed::PrivateItem(Some((item, date)))) => 
                Processed::Discover(Record::from_item(item, *read).ok().and_then(|record| {
                parent_header.validate_child(&record.header).ok()?;
                let header = if record.header.protocol_id() == Id::MAX {
                    serde_json::from_slice::<Header>(&record.header.2).ok().and_then(|h| 
                        parent_header.validate_child(&h).is_ok().then_some(h)
                    ).filter(|h| h.3 != Id::MAX)?
                } else {
                    protocols.iter().find_map(|p| (p.id() == record.header.3).then(|| {
                        let my_header = cache.header(parent, &**p, *index).ok()?;
                        (my_header.id() == record.header.id()).then_some(my_header)
                    })).flatten().unwrap_or(record.header)
                };

                let id = header.id();
                cache.cache(parent.clone(), header);
                Some((parent.join(id), date))
            })),
            (MidState::Create(record, path), super::Processed::PrivateItem(item)) => Processed::Create(
                path.clone(), item.and_then(|(item, date)| Record::from_item(item, *record.header.0.read).map(|r| (*record != r).then_some(r)).transpose().map(|r| (r, date)))
            ),
            (MidState::Read(read, id), super::Processed::PrivateItem(item)) => Processed::Read(
                item.and_then(|(item, date)| Record::from_item(item, *read).ok().map(|r| (r, date)).filter(|(r,_)| Id::hash(&r.header) == *id))
            ),
            (MidState::Update, super::Processed::Empty) => Processed::Update(true),
            (MidState::Update, super::Processed::DeleteKey(_)) => Processed::Update(false),
            (MidState::Delete, super::Processed::Empty) => Processed::Delete(true),
            (MidState::Delete, super::Processed::DeleteKey(_)) => Processed::Delete(false),
            (MidState::Share, super::Processed::Empty) => Processed::Share,
            (MidState::Receive, super::Processed::ReadDM(sent)) => {
                Processed::Receive(sent.into_iter().flat_map(|(s, p)| {
                    let header = serde_json::from_slice::<Header>(&p).ok()?;
                    header.validate().ok()?;
                    let id = Id::hash(&header);
                    let parent = RecordPath(vec![Id::MAX]);
                    let path = parent.join(id);
                    cache.cache(parent, header);
                    Some((s, path))
                }).collect())//TODO: Include who sent the record /fff/bob
            },
            res => {return Err(Error::mr(res));}
        })
    }
}
