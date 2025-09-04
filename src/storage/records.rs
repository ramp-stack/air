use easy_secp256k1::{EasySecretKey, EasyPublicKey};
use secp256k1::{SecretKey, PublicKey};
use serde::{Serialize, Deserialize};
use std::collections::BTreeMap;
use std::hash::{Hasher, Hash};
use std::ops::{DerefMut, Deref};
use std::cmp::Ordering;
use std::fmt::Debug;

use crate::{DateTime, Id};
use crate::orange_name::{self, OrangeResolver, OrangeSecret, OrangeName, Endpoint};
use crate::server::{Request, Response, Command, Context};
use super::PrivateItem;

use active_rusqlite::*;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Hash)]
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
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {write!(f, "{self:?}")}
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Hash)]
pub enum Error {
    MaliciousResponse(String),
    ConnectionFailed(String),
    Validation(ValidationError),
    SerdeJson(String),
    EasySecp256k1(String),
    CriticalOrange(String),
    ///In order to run this command the Cache must be loaded into the Store
    MissingCache
}
impl Error {pub(crate) fn mr(e: impl Debug) -> Self {Error::MaliciousResponse(format!("{e:?}"))}}
impl From<serde_json::Error> for Error {fn from(e: serde_json::Error) -> Error {Error::SerdeJson(format!("{e:?}"))}}
impl From<easy_secp256k1::Error> for Error {fn from(e: easy_secp256k1::Error) -> Error {Error::EasySecp256k1(format!("{e:?}"))}}
impl From<orange_name::Error> for Error {fn from(error: orange_name::Error) -> Self {match error{
    orange_name::Error::Critical(error) => {Error::CriticalOrange(error)}
    resolution => Error::ConnectionFailed(format!("{resolution:?}")),
}}}
impl From<crate::server::Error> for Error {fn from(e: crate::server::Error) -> Error {match e {
    crate::server::Error::MaliciousResponse(response) => Error::MaliciousResponse(response),
    crate::server::Error::ConnectionFailed(error) => Error::ConnectionFailed(error),
    crate::server::Error::CriticalOrange(error) => Error::CriticalOrange(error),
}}}
impl From<ValidationError> for Error {fn from(e: ValidationError) -> Self {Error::Validation(e)}}
impl std::error::Error for Error {}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {write!(f, "{self:?}")}
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

#[derive(Default, Debug, Clone, PartialEq, Eq, Hash, Ord, PartialOrd)]
#[derive(serde_with::SerializeDisplay)]
#[derive(serde_with::DeserializeFromStr)]
pub struct RecordPath(Vec<Id>);
impl RecordPath {
    pub fn root() -> Self {RecordPath(vec![])}
    pub fn parent(&self) -> Option<Self> {
        self.0.split_last().map(|t| RecordPath(t.1.to_vec()))
    }
    pub fn last(&self) -> Id {self.0.last().copied().unwrap_or(Id::MIN)}
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
    pub fn path(&self) -> &RecordPath {&self.0}
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
    pub const fn new(children: Option<(bool, bool)>, delete: Option<bool>, keys: BTreeMap<String, bool>) -> Self {
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
pub struct Children {
    pub allowed_protocols: Vec<Id>,
    /// Can anyone with access to this protocol discover all children?
    pub anyone_discover: bool,
    /// Can anyone with access to this protocol read all children?
    pub anyone_read: bool,
    /// Can anyone with access to this protocol create pointers to children?
    pub allow_pointers: bool,
}
impl Children {
    pub const fn new(allowed_protocols: Vec<Id>, anyone_discover: bool, anyone_read: bool, allow_pointers: bool) -> Self {
        Children{allowed_protocols, anyone_discover, anyone_read, allow_pointers}
    }
}
 
#[derive(Serialize, Deserialize, PartialEq, Eq, Clone, Debug, Default, Hash)]
pub struct Protocol {
    pub name: String, 
    pub children: Option<Children>,
    ///Some if delete is possible, true if delete must be secret
    pub delete: Option<(KeyGen, bool)>,
    ///Additional Keys, true if it must be secret
    pub others: BTreeMap<String, (KeyGen, bool)>,
    ///Allow extra keys not listed above
    pub allow_extra_keys: bool
}
impl Protocol {
    pub fn new(name: &str, children: Option<Children>, delete: Option<(KeyGen, bool)>, others: BTreeMap<String, (KeyGen, bool)>, allow_extra_keys: bool) -> Self {
        Protocol{name: name.to_string(), children, delete, others, allow_extra_keys}
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
        self.delete.as_ref().map(|(_, d)| {
            let key_delete = keyset.delete.ok_or(ValidationError::ActionMismatch("Delete".to_string()))?;
            if *d && key_delete.secret().is_none() {return Err(ValidationError::MissingPerms("Delete".to_string()));}
            Ok(())
        }).transpose()?;
        if !self.allow_extra_keys && (keyset.others.keys().collect::<Vec<_>>() != self.others.keys().collect::<Vec<_>>()) {
            return Err(ValidationError::ActionMismatch("Extra Keys".to_string()));
        }
        for (n, (_, secret)) in &self.others {
            let ok = keyset.others.get(n).ok_or(ValidationError::ActionMismatch(format!("Missing Key {n}")))?;
            if *secret && ok.secret().is_none() {return Err(ValidationError::MissingPerms(n.to_string()));}                
        }
        Ok(())
    }
    fn is_child(&self, id: &Id) -> bool {
        self.children.as_ref().map(|c|
            c.allowed_protocols.contains(id) || 
            c.allowed_protocols.is_empty() ||
            (c.allow_pointers && *id == Pointer::id())
        ).unwrap_or_default()
    }
}

#[derive(ActiveRecord, SerdeJsonToFromStr, Serialize, Deserialize, PartialEq, Eq, Clone, Debug, Hash)]
pub struct Header(KeySet, Protocol, Vec<u8>);
impl Header {
    pub fn keys(&self) -> &KeySet {&self.0}
    pub fn protocol_id(&self) -> Id {self.1.id()}
    pub fn id(&self) -> Id {Id::hash(&self)}
    pub fn data(&self) -> &[u8] {&self.2}

    fn validate(&self) -> Result<(), ValidationError> {self.1.validate(&self.0)}
    fn validate_child(&self, child: &Self) -> Result<(), ValidationError> {
        if self.1.is_child(&child.1.id()) {return Ok(());}
        Err(ValidationError::InvalidProtocol(child.1.id()))
    }

    pub fn max(self, other: Self) -> Result<Self, ValidationError> {
        Ok(Header(self.0.max(other.0)?, self.1, self.2)) 
    }

    fn set(mut self, perms: &Permissions) -> Result<Self, ValidationError> {
        self.0 = self.0.set(perms)?;
        self.validate()?;
        Ok(self)
    }

    fn de_enc(header: Vec<u8>, read: SecretKey) -> Result<Header, ValidationError> {
        let header: Header = serde_json::from_slice(
            &read.easy_decrypt(&header).map_err(|e| ValidationError::Decryption(e.to_string()))?
        ).map_err(|e| ValidationError::Deserialization(e.to_string()))?;
        if *header.0.read != read {return Err(ValidationError::DifferentKeys("Read".to_string()));}
        header.validate()?;
        Ok(header)
    }

    fn derive(cache: &Cache, parent: &RecordPath, protocol: Protocol, header_data: Vec<u8>, index: u32) -> Result<Header, Error> {
        let protocol_id = protocol.id();
        let mkey = cache.get_root().derive(parent)?.index(index)?;
        let discover_child = mkey.easy_derive(&[0])?;
        let read_child = mkey.easy_derive(&[1])?;
        let record_key = mkey.easy_derive(&[2])?;
        let delete = protocol.delete.as_ref().map(|(d, _)| d.get(&record_key)).transpose()?;
        let others = protocol.others.iter().map(|(n, (k, _))| Ok((n.to_string(), k.get(&record_key)?))).collect::<Result<BTreeMap<String, Key>, easy_secp256k1::Error>>()?;
        let parent_h = cache.get(parent).ok_or(ValidationError::MissingRecord(parent.to_string()))?;
        if !parent_h.1.is_child(&protocol_id) {return Err(ValidationError::InvalidProtocol(protocol_id).into());}
        let children = parent_h.0.children.ok_or(ValidationError::InvalidParent(parent.to_string()))?;
        let discover = children.0.secret().ok_or(ValidationError::MissingPerms("DiscoverChild".to_string()))?.easy_derive(&[index])?;
        let read = children.1.secret().ok_or(ValidationError::MissingPerms("ReadChild".to_string()))?.easy_derive(&[index])?;
        let header = Header(
            KeySet{
                discover: WSecretKey(discover),
                read: WSecretKey(read),
                children: protocol.children.as_ref().map(|_| (
                    Key::Secret(discover_child.into()),
                    Key::Secret(read_child.into())
                )),
                delete,
                others,
            },
            protocol,
            header_data
        );
        header.validate()?;
        Ok(header)
    }

    fn root(root: &PathedKey) -> Result<Header, Error> {
        Ok(Header(
            KeySet {
                discover: root.as_ref().easy_derive(&[2])?.into(),
                read: root.as_ref().easy_derive(&[3])?.into(),
                children: Some((
                    Key::Secret(root.as_ref().easy_derive(&[0])?.into()),
                    Key::Secret(root.as_ref().easy_derive(&[1])?.into())
                )),
                delete: None,
                others: BTreeMap::default()
            }, 
            Protocol::new("ROOT", Some(Children::new(vec![], true, true, true)), None, BTreeMap::default(), false),
            vec![]
        ))
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

pub type Keys = BTreeMap<String, KeyGen>;

#[derive(Serialize, Deserialize, PartialEq, Eq, Clone, Debug, Hash)]
pub enum KeyGen {
    Static(Key),
    Derive(u32),
}
impl KeyGen {
    fn get(&self, key: &SecretKey) -> Result<Key, easy_secp256k1::Error> {
        Ok(match self {
            KeyGen::Static(key) => *key,
            KeyGen::Derive(i) => Key::Secret(key.easy_derive(&[*i])?.into())
        })
    }
}

#[derive(Clone, Debug)]
struct Pointer;
impl Pointer {
    fn get_protocol() -> Protocol {Protocol::new(
        "Pointer", None, None, BTreeMap::new(), false
    )}
    fn id() -> Id {Self::get_protocol().id()}
}




#[derive(ActiveRecord, Serialize, Deserialize, Clone)]
pub struct Cache(
    PathedKey,
    #[active_record(child)]
    BTreeMap<Id, Stateless<Header>>,
);

//ROOT is imaginary and so if the pathed key points to a protocol folder creating records
//under root that really fall under a protocol folder won't cause issues unless someone with the
//protocol folder attempts to discover the children which don't conform to the parent.
//
//Only use not Root keys after establishing trust that they will only use this to store valid data
//Or else the data will be lost to anyone with higher permission
impl Cache {
    pub fn new(root: PathedKey) -> Self {
        let header = Header::root(&root).unwrap();
        let header_id = Id::MIN;
        Cache(root, BTreeMap::from([(header_id, Stateless(header))]))
    }

    fn get(&self, path: &RecordPath) -> Option<&Header> {
        self.1.get(&path.last()).map(|h| &**h)
    }

    fn cache(&mut self, header: Header) {
        match self.1.get_mut(&header.id()) {
            Some(h) => {
                **h = Header::clone(h).max(header).unwrap();
            },
            None => {self.1.insert(header.id(), Stateless(header));}
        }
    }

    fn get_root(&self) -> &PathedKey {&self.0}
}
impl std::fmt::Debug for Cache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_map().entries(self.1.iter().map(|(id, h)| (id.to_string(), format!("{h:?}")))).finish()
    }
}





#[derive(Serialize, Deserialize)]
pub struct Discover{parent: RecordPath, index: u32, endpoint: Endpoint}
impl Discover {
    pub fn new(parent: &RecordPath, index: u32, endpoint: Endpoint) -> Self {
        Discover{parent: parent.clone(), index, endpoint}
    }
}
impl Command for Discover {
    type Output = Result<Option<(DateTime, Option<RecordPath>)>, Error>;

    async fn run(self, mut ctx: Context) -> Self::Output {
        let parent_header = ctx.try_get_mut::<Cache>().await.ok_or(Error::MissingCache)?
            .get(&self.parent).ok_or(ValidationError::MissingRecord(self.parent.to_string()))?
            .clone();
        let children = parent_header.0.children.and_then(|(d, r)| d.secret().map(|d| (d, r))).ok_or(ValidationError::InvalidParent(self.parent.to_string()))?;
        let discover = children.0.easy_derive(&[self.index])?;
        let read = children.1.secret().map(|r| r.easy_derive(&[self.index]).unwrap());
        let request = ctx.run(super::requests::ReadPrivateHeader::new(&discover, self.endpoint)).await?;
        let mut cache = ctx.try_get_mut::<Cache>().await.ok_or(Error::MissingCache)?;
        Ok(match (read, request) {
            (_, None) => None,
            (None, Some((date, _))) | (_, Some((date, None))) => Some((date, None)),
            (Some(read), Some((date, Some(header)))) => Some((date, Header::de_enc(header, read).ok().and_then(|header| {
                parent_header.validate_child(&header).ok()?;
                let header = if header.protocol_id() == Pointer::id() {
                    serde_json::from_slice::<Header>(&header.2).ok().and_then(|h| 
                        parent_header.validate_child(&h).is_ok().then_some(h)
                    ).filter(|h| h.protocol_id() != Pointer::id())?
                } else {
                    let protocol = &header.1;
                    let my_header = Header::derive(&cache, &self.parent, protocol.clone(), header.2.clone(), self.index).ok()?;
                    if my_header.id() == header.id() {my_header} else {header}
                };

                let id = header.id();
                cache.cache(header);
                Some(self.parent.join(id))
            })))
        })
    }
}



//      pub fn create(cache: &mut Cache, parent: &RecordPath, protocol: Protocol, header_data: Vec<u8>, index: u32, perms: &Permissions, payload: Vec<u8>) -> Result<Self, Error> {
//          let o_header = Header::derive(cache, parent, protocol, header_data, index)?;
//          let header = o_header.clone().set(perms)?;
//          let record = Record{header, payload};
//          let discover = &record.header.0.discover;
//          let delete = record.header.0.delete.map(|d| d.public());
//          let payload = record.header.0.read.easy_public_key().easy_encrypt(serde_json::to_vec(&record)?)?;
//          let enc_header = record.header.0.read.easy_public_key().easy_encrypt(serde_json::to_vec(&record.header)?)?;
//          let path = parent.join(record.header.id());
//          Ok(Client(super::Client::create_private(discover, delete, enc_header, payload), MidState::Create(path, o_header)))
//      }



#[derive(Serialize, Deserialize)]
pub struct Create{
    parent: RecordPath,
    protocol: Protocol,
    header_data: Vec<u8>,
    index: u32,
    perms: Permissions,
    payload: Vec<u8>,
    endpoint: Endpoint
}
impl Create {
    pub fn new(parent: RecordPath, protocol: Protocol, header_data: Vec<u8>, index: u32, perms: Permissions, payload: Vec<u8>, endpoint: Endpoint) -> Self {
        Create{parent, protocol, header_data, index, perms, payload, endpoint}
    }
}
impl Command for Create {
    type Output = Result<(RecordPath, Option<DateTime>), Error>;

    async fn run(self, mut ctx: Context) -> Self::Output {
        let o_header = Header::derive(
            &*ctx.try_get_mut::<Cache>().await.ok_or(Error::MissingCache)?,
            &self.parent, self.protocol, self.header_data, self.index
        )?;
        let header = o_header.clone().set(&self.perms)?;
        let record = Record{header, payload: self.payload};
        let discover = &record.header.0.discover;
        let delete = record.header.0.delete.map(|d| d.public());
        let payload = record.header.0.read.easy_public_key().easy_encrypt(serde_json::to_vec(&record)?)?;
        let enc_header = record.header.0.read.easy_public_key().easy_encrypt(serde_json::to_vec(&record.header)?)?;
        let path = self.parent.join(record.header.id());
        let date = ctx.run(super::requests::CreatePrivate::new(discover, delete, enc_header, payload, self.endpoint)).await?;
        ctx.try_get_mut::<Cache>().await.ok_or(Error::MissingCache)?.cache(o_header);
        Ok((path.clone(), date))
    }
}



//  #[derive(Debug)]
//  enum MidState {
//      Discover(Option<SecretKey>, Header, RecordPath, u32),
//      Create(RecordPath, Header),
//      Read(SecretKey, Id),
//      Delete,
//      Share,
//      Receive,
//  }

//  #[allow(clippy::large_enum_variant)]
//  #[derive(PartialEq)]
//  pub enum Processed {
//      Discover(Option<(DateTime, Option<RecordPath>)>),
//      Create(RecordPath, Option<DateTime>),
//      Read(Option<(DateTime, Option<Record>)>),
//      Delete(bool),
//      Receive(Vec<(OrangeName, RecordPath)>),
//      Empty
//  }

//  pub struct Client(super::Client, MidState);
//  impl Client {
//      pub fn discover(cache: &mut Cache, parent: &RecordPath, index: u32) -> Result<Self, Error> { 
//          let header = cache.get(parent).ok_or(ValidationError::MissingRecord(parent.to_string()))?;
//          let children = header.0.children.and_then(|(d, r)| d.secret().map(|d| (d, r))).ok_or(ValidationError::InvalidParent(parent.to_string()))?;
//          let discover = children.0.easy_derive(&[index])?;
//          let read = children.1.secret().map(|r| r.easy_derive(&[index]).unwrap());
//          Ok(Client(super::Client::read_private_header(&discover), MidState::Discover(read, header.clone(), parent.clone(), index)))
//      }

//      pub fn create(cache: &mut Cache, parent: &RecordPath, protocol: Protocol, header_data: Vec<u8>, index: u32, perms: &Permissions, payload: Vec<u8>) -> Result<Self, Error> {
//          let o_header = Header::derive(cache, parent, protocol, header_data, index)?;
//          let header = o_header.clone().set(perms)?;
//          let record = Record{header, payload};
//          let discover = &record.header.0.discover;
//          let delete = record.header.0.delete.map(|d| d.public());
//          let payload = record.header.0.read.easy_public_key().easy_encrypt(serde_json::to_vec(&record)?)?;
//          let enc_header = record.header.0.read.easy_public_key().easy_encrypt(serde_json::to_vec(&record.header)?)?;
//          let path = parent.join(record.header.id());
//          Ok(Client(super::Client::create_private(discover, delete, enc_header, payload), MidState::Create(path, o_header)))
//      }

//      pub fn read(cache: &mut Cache, path: &RecordPath) -> Result<Self, Error> {
//          let header = cache.get(path).ok_or(ValidationError::MissingRecord(path.to_string()))?;
//          Ok(Client(super::Client::read_private(&header.0.discover), MidState::Read(*header.0.read, Id::hash(&header))))
//      }

//      pub fn delete(cache: &mut Cache, path: &RecordPath) -> Result<Self, Error> {
//          let header = cache.get(path).ok_or(ValidationError::MissingRecord(path.to_string()))?;
//          let discover = header.0.discover.easy_public_key();
//          let delete = header.0.delete.and_then(|d| d.secret()).ok_or(ValidationError::MissingPerms("Delete".to_string()))?;
//          Ok(Client(super::Client::delete_private(discover, &delete), MidState::Delete))
//      }

//      pub async fn share(cache: &mut Cache, resolver: &mut OrangeResolver, secret: &OrangeSecret, recipient: &OrangeName, perms: &Permissions, path: &RecordPath) -> Result<Self, Error> {
//          let header = &cache.get(path).ok_or(ValidationError::MissingRecord(path.to_string()))?.0;
//          let header = header.clone().set(perms)?;
//          Ok(Client(super::Client::create_dm(resolver, secret, recipient.clone(), serde_json::to_vec(&header)?).await?, MidState::Share))
//      }

//      pub async fn receive(resolver: &mut OrangeResolver, secret: &OrangeSecret, since: DateTime) -> Result<Self, Error> {
//          Ok(Client(super::Client::read_dm(resolver, secret, since).await?, MidState::Receive))
//      }

//      pub fn create_pointer(cache: &mut Cache, parent: &RecordPath, record: &RecordPath, index: u32) -> Result<Self, Error> {
//          let record_header = cache.get(record).ok_or(ValidationError::MissingRecord(record.to_string()))?.clone();
//          let header = Header::derive(cache, parent, Pointer::get_protocol(), serde_json::to_vec(&record_header)?, index)?;
//          let record = Record{header: header.clone(), payload: vec![]};
//          let discover = &record.header.0.discover;
//          let delete = record.header.0.delete.map(|d| d.public());
//          let payload = record.header.0.read.easy_public_key().easy_encrypt(serde_json::to_vec(&record)?)?;
//          let enc_header = record.header.0.read.easy_public_key().easy_encrypt(serde_json::to_vec(&record.header)?)?;
//          Ok(Client(super::Client::create_private(discover, delete, enc_header, payload), MidState::Create(parent.join(Id::hash(&header)), record_header)))
//      }

//      pub fn build_request(&self) -> Request {self.0.build_request()}

//      pub async fn process_responses(&self, cache: &mut Cache, resolver: &mut OrangeResolver, responses: Vec<Response>) -> Result<Option<Processed>, Error> {
//          let req = (responses.len() / 2) + 1;//Divide by two round down add one
//          let mut processed = Vec::new();
//          for response in responses {
//              processed.push(self.process_response(cache, resolver, response).await?);
//          }

//          let (count, winner) = processed.into_iter().fold((0, None), |mut acc, p| {
//              if acc.0 == 0 {acc.1 = Some(p);}
//              else if acc.1 == Some(p) {acc.0 += 1;}
//              else {acc.0 -= 1;}
//              acc
//          });
//          Ok(if count >= req {Some(winner.unwrap())} else {None})
//      }

//      pub async fn process_response(&self, cache: &mut Cache, resolver: &mut OrangeResolver, response: Response) -> Result<Processed, Error> {
//          Ok(match (&self.1, self.0.process_response(resolver, response).await?) {
//              (MidState::Discover(_,_,_,_), super::Processed::PrivateHeader(None)) => Processed::Discover(None),
//              (MidState::Discover(None, _, _, _), super::Processed::PrivateHeader(Some((date, _)))) => {
//                  Processed::Discover(Some((date, None)))
//              },
//              (
//                  MidState::Discover(Some(read), parent_header, parent, index),
//                  super::Processed::PrivateHeader(Some((date, Some(header))))
//              ) => {
//                  Processed::Discover(Some((date, Header::de_enc(header, *read).ok().and_then(|header| {
//                      parent_header.validate_child(&header).ok()?;
//                      let header = if header.protocol_id() == Pointer::id() {
//                          serde_json::from_slice::<Header>(&header.2).ok().and_then(|h| 
//                              parent_header.validate_child(&h).is_ok().then_some(h)
//                          ).filter(|h| h.protocol_id() != Pointer::id())?
//                      } else {
//                          let protocol = &header.1;
//                          let my_header = Header::derive(cache, parent, protocol.clone(), header.2.clone(), *index).ok()?;
//                          if my_header.id() == header.id() {my_header} else {header}
//                      };

//                      let id = header.id();
//                      cache.cache(header);
//                      Some(parent.join(id))
//                  }))))
//              },
//              (MidState::Create(path, o_header), super::Processed::PrivateCreate(date)) => {
//                  cache.cache(o_header.clone());
//                  Processed::Create(path.clone(), date)
//              },
//              (MidState::Read(read, id), super::Processed::PrivateItem(item)) => Processed::Read(
//                  item.map(|(date, item)| (date, item.and_then(|item| Record::from_item(item, *read).ok()).filter(|r| Id::hash(&r.header) == *id)))
//              ),
//              (MidState::Delete, super::Processed::Empty) => Processed::Delete(true),
//              (MidState::Delete, super::Processed::DeleteKey(_)) => Processed::Delete(false),
//              (MidState::Share, super::Processed::Empty) => Processed::Empty,
//              (MidState::Receive, super::Processed::ReadDM(sent)) => {
//                  Processed::Receive(sent.into_iter().flat_map(|(s, p)| {
//                      let header = serde_json::from_slice::<Header>(&p).ok()?;
//                      header.validate().ok()?;
//                      let id = Id::hash(&header);
//                      let parent = RecordPath(vec![Pointer::id()]);
//                      let path = parent.join(id);
//                      cache.cache(header);
//                      Some((s, path))
//                  }).collect())//TODO: Include who sent the record /fff/bob
//              },
//              res => {return Err(Error::mr(res));}
//          })
//      }
//  }


//  //Records are currently Identifyable by its header Id because the header contains the keys used to
//  //locate it on any air server and the header data is where all the tags are located
//  //
//  //
//  //If I used name paths /rooma/messages/message21 could point to different records at any path level
//  //Unless I can prove that /rooma/messages corrosponds with /abc/efg without any data but my master key
//  //
//  //Given my master key and /rooma/messages/message21 locate the same record no matter the state
//  //
//  //1. Discover every record under / until one has "rooma" in the header data will not work because
//  //   the original can be deleted an a different record can be created at another index with the
//  //   same name
//  //2. Discovery order is unimportant 
//  //
//  //Derive a series of bytes by adding 256 to each one 
//  //Reservig 0-255 for special characters
//  //0 is used to deleminate pathes
//  //
//  //
//  //
//  //Map with deletes disabled is possible because you will always created your index at the next open
//  //position and unless a previouse record claimed that index you have it
//  //
//  //Map with deletes enabled requires looking for VCs from the air server on any records that have
//  //been corupted and will therefore be skipped claimed indexs are then
//  //
//  //
//  //
//  //Structures will contain the header id of its children 
//  //Maps cannot because their children is unknown
//  //
//  //BTreeMap => Named Map 
//  //BTreeSet => Unordered list
//  //Vec => Ordered List
//  //
//  //When working with ordered list air server indexs are not resuable
//  //
//  //
//  //Never let records without a delete key expires okay if its more expensive
//  //













//  //  pub enum CreatePrivate{
//  //      New(RecordPath, Protocol, Vec<u8>, u32, Permissions, Vec<u8>, Vec<Endpoint>),
//  //      Wating(RecordPath, Header)
//  //  }
//  //  impl CreatePrivate {
//  //      pub fn new(
//  //          parent: RecordPath, protocol: Protocol, header_data: Vec<u8>, index: u32, perms: Permissions, payload: Vec<u8>, endpoints: Vec<Endpoint>
//  //      ) -> Self {
//  //          CreatePrivate::New(parent, protocol, header_data, index, perms, payload, endpoints)
//  //      }

//  //  }
//  //  impl MultiReqest for CreatePrivate {
//  //      fn run(&mut self, resolver, secret, state, responses) -> {match *self {
//  //          Self::New(parent, protocol, header_data, index, perms, payload, endpoints) => Status {
//  //              let cache: &mut Cache = state.get_mut_or_default();
//  //              let o_header = Header::derive(cache, parent, protocol, header_data, index)?;
//  //              let header = o_header.clone().set(perms)?;
//  //              let record = Record{header, payload};
//  //              let discover = &record.header.0.discover;
//  //              let delete = record.header.0.delete.map(|d| d.public());
//  //              let payload = record.header.0.read.easy_public_key().easy_encrypt(serde_json::to_vec(&record)?)?;
//  //              let enc_header = record.header.0.read.easy_public_key().easy_encrypt(serde_json::to_vec(&record.header)?)?;
//  //              let path = parent.join(record.header.id());
//  //              self = CreatePrivate::Waiting(path, o_header);
//  //              Status::request(CreatePrivate::new(discover, delete, enc_header, payload, endpoints))
//  //          },
//  //          Self::Wating(path, o_header), Some(created) => {

//  //          }
//  //      }}
//  //      fn responses(&mut self, responses: Vec<Vec<ChandlerResponse>>) -> {

//  //      }
//  //  }



