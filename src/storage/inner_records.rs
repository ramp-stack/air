use serde::{Serialize, Deserialize};
use easy_secp256k1::{Signed as KeySigned, EasySecretKey, EasyPublicKey};
use secp256k1::{SecretKey, PublicKey};
use orange_name::{OrangeResolver, OrangeSecret, OrangeName, Signed as DidSigned, Endpoint};

use std::collections::BTreeMap;
use std::hash::{Hasher, Hash};
use std::ops::{DerefMut, Deref};
use std::cmp::Ordering;
use std::fmt::Debug;

use crate::Id;

type DateTime = chrono::DateTime<chrono::Utc>;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Hash)]
pub enum ValidationError {
    ///Key presence mismatched with protocol
    KeyMismatch(String),
    ///Action requires this secret key and it was not present
    ///When combining permissions two different keys for the same action were found
    DifferentKeys(String),
    Deserialization(String),
    Decryption(String),
    InvalidChildProtocol(Id),
}
impl std::error::Error for ValidationError {}
impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {write!(f, "{self:?}")}
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Hash)]
pub enum Error {
    MissingPerms(String),
    MissingRecord(RecordPath),
    InvalidParent(RecordPath),
    Validation(ValidationError),
    SerdeJson(String),
    Secp256k1(String),
    OrangeName(String),
}
impl From<serde_json::Error> for Error {fn from(e: serde_json::Error) -> Error {Error::SerdeJson(format!("{e:?}"))}}
impl From<secp256k1::Error> for Error {fn from(e: secp256k1::Error) -> Error {Error::Secp256k1(format!("{e:?}"))}}
impl From<orange_name::Error> for Error {fn from(e: orange_name::Error) -> Error {
    Error::OrangeName(format!("{e:?}"))
}}
impl From<ValidationError> for Error {fn from(e: ValidationError) -> Error {Error::Validation(e)}}
impl std::error::Error for Error {}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {write!(f, "{self:?}")}
}

#[derive(Serialize, Deserialize, Clone, Debug, Hash)]
pub struct PrivateItem {
    pub discover: PublicKey,
    pub delete: Option<PublicKey>,
    pub header: KeySigned<Vec<u8>>,
    pub payload: Vec<u8>
}
impl PrivateItem {
    pub fn new(discover: &SecretKey, delete: Option<PublicKey>, header: Vec<u8>, payload: Vec<u8>) -> KeySigned<Self> {
        KeySigned::new(PrivateItem{discover: discover.easy_public_key(), delete, header: KeySigned::new(header, discover), payload}, discover)
    }

    pub fn verify(signed: KeySigned<Self>, key: PublicKey) -> Result<PrivateItem, secp256k1::Error> {
        signed.verify().and_then(|_|
            (*signed.signer() != key || signed.as_ref().discover != key).then_some(signed.into_inner()
        ).ok_or(secp256k1::Error::InvalidMessage))
    }

    pub fn verify_header(signed: KeySigned<Vec<u8>>, key: PublicKey) -> Result<Vec<u8>, secp256k1::Error> {
        signed.verify().and_then(|_| (*signed.signer() != key).then_some(signed.into_inner()).ok_or(secp256k1::Error::InvalidMessage))
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, Hash)]
pub struct DMItem(OrangeName, Vec<u8>);

impl DMItem {
    pub async fn new(resolver: &mut OrangeResolver, secret: &OrangeSecret, recipient: OrangeName, payload: Vec<u8>) -> Result<Self, orange_name::Error>{
        let com = resolver.key(&recipient, Some("easy_access_com"), None).await?;
        let signed = DidSigned::new(resolver, secret, payload).await?;
        Ok(DMItem(recipient, com.easy_encrypt(serde_json::to_vec(&signed).unwrap()).unwrap()))
    }

    pub async fn verify(self, resolver: &mut OrangeResolver, secret: &OrangeSecret) -> Result<(OrangeName, Vec<u8>), orange_name::Error> {
        let name = secret.name();
        let key = resolver.secret_key(secret, Some("easy_access_com"), None).await?;
        let signed = serde_json::from_slice::<DidSigned<Vec<u8>>>(&key.easy_decrypt(&self.1)?).map_err(|_| secp256k1::Error::InvalidMessage)?;
        Ok((signed.verify(resolver, None).await?, signed.into_inner()))
    }
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Clone, Debug, Hash)]
pub struct Record {
    pub header: Header,
    pub payload: Vec<u8>
}
impl Record {
    pub fn new(cache: &mut Cache, enc_key: &PathedKey, parent: &RecordPath, protocol: Protocol, header_data: Vec<u8>, index: u32, payload: Vec<u8>) -> Result<Self, Error> {
        let header = Header::new(
            cache, enc_key, parent, protocol, header_data, index
        )?;
        cache.cache(header.clone());
        Ok(Record{header, payload})
    }

    fn from_item(item: PrivateItem, read: SecretKey) -> Result<Record, ValidationError> {
        let record: Record = serde_json::from_slice(
            &read.easy_decrypt(&item.payload).map_err(|e| ValidationError::Decryption(e.to_string()))?
        ).map_err(|e| ValidationError::Deserialization(e.to_string()))?;
        if record.header.0.discover.easy_public_key() != item.discover {return Err(ValidationError::DifferentKeys("Discover".to_string()));}
        if record.header.0.read != read {return Err(ValidationError::DifferentKeys("Read".to_string()));}
        if record.header.0.delete.map(|d| d.public()) != item.delete {return Err(ValidationError::DifferentKeys("ItemDelete".to_string()));}
        record.header.validate()?;
        Ok(record)
    }

    fn to_item(&self) -> Result<KeySigned<PrivateItem>, secp256k1::Error> {
        let discover = &self.header.0.discover;
        let delete = self.header.0.delete.map(|d| d.public());
        let payload = self.header.0.read.easy_public_key().easy_encrypt(serde_json::to_vec(&self).unwrap())?;
        let enc_header = self.header.0.read.easy_public_key().easy_encrypt(serde_json::to_vec(&self.header).unwrap())?;
        Ok(PrivateItem::new(discover, delete, enc_header, payload))
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Cache(
    PathedKey,
    BTreeMap<Id, Header>,
);

impl Cache {
    ///Returns ValidationError::MissingRecord if it cannot be found
    fn get(&self, path: &RecordPath) -> Result<&Header, ValidationError> {
        self.1.get(&path.last()).ok_or(ValidationError::MissingRecord(path.to_string()))
    }

    fn cache(&mut self, header: Header) {
        match self.1.get_mut(&header.id()) {
            Some(h) => {
                *h = Header::clone(h).max(header).unwrap();
            },
            None => {self.1.insert(header.id(), header);}
        }
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
        let check = |b: bool, a: &str| b.then_some(()).ok_or(ValidationError::KeyMismatch(a.to_string()));
        check(self.children.is_some() != self.children.is_some(), "Needs Children Keys")?;
        self.children.as_ref().map(|cv| {
            let children = keyset.children_keys()?;
            check(cv.anyone_discover && children.0.secret().is_none(), "Needs Secret DiscoverChild")?;
            check(cv.anyone_read && children.1.secret().is_none(), "Needs Secret ReadChild")
        }).transpose()?;
        self.delete.as_ref().map(|(_, d)| {
            check(*d && keyset.delete()?.secret().is_none(), "Needs Secret Delete")
        }).transpose()?;
        check(
            !self.allow_extra_keys && (keyset.others.keys().collect::<Vec<_>>() != self.others.keys().collect::<Vec<_>>()),
            "Has Extra Keys"
        )?;
        for (n, (_, secret)) in &self.others {
            check(*secret && keyset.get_other(n)?.secret().is_none(), &format!("Needs Secret {n}"))?;                
        }
        Ok(())
    }

    fn validate_child(&self, id: &Id) -> Result<(), ValidationError> {
        if self.children.as_ref().map(|c|
            c.allowed_protocols.contains(id) || 
            c.allowed_protocols.is_empty() ||
            (c.allow_pointers && *id == Pointer::id())
        ).unwrap_or_default() {
            Ok(())
        } else {Err(ValidationError::InvalidChildProtocol(*id))}
    }
}

//TODO: Header needs to contain the endpoints and the hash of the payload(encrypted payload?)

#[derive(Serialize, Deserialize, PartialEq, Eq, Clone, Debug, Hash)]
pub struct Header(KeySet, Protocol, Vec<u8>);
impl Header {
    pub fn keys(&self) -> &KeySet {&self.0}
    pub fn protocol_id(&self) -> Id {self.1.id()}
    pub fn id(&self) -> Id {Id::hash(&self)}
    pub fn data(&self) -> &[u8] {&self.2}

    pub fn validate(&self) -> Result<(), ValidationError> {self.1.validate(&self.0)}

  //fn max(self, other: Self) -> Result<Self, ValidationError> {
  //    Ok(Header(self.0.max(other.0), self.1, self.2)) 
  //}

    pub fn set(mut self, perms: &Permissions) -> Result<Self, ValidationError> {
        self.0 = self.0.set(perms)?;
        self.validate()?;
        Ok(self)
    }

    pub fn decrypt(encrypted: Vec<u8>, read: SecretKey) -> Result<Header, ValidationError> {
        let header: Header = serde_json::from_slice(
            &read.easy_decrypt(&encrypted).map_err(|e| ValidationError::Decryption(e.to_string()))?
        ).map_err(|e| ValidationError::Deserialization(e.to_string()))?;
        if header.0.read != read {return Err(ValidationError::DifferentKeys("Read".to_string()));}
        header.validate()?;
        Ok(header)
    }

    pub fn create_pointer(&self, cache: &Cache, enc_key: &PathedKey, parent: &RecordPath, index: u32) -> Result<Self, Error> {
        Header::new(cache, enc_key, parent, Pointer::get_protocol(), serde_json::to_vec(&self)?, index)
    }

    pub fn decode_pointer(&self) -> Option<Self> {
        (self.protocol_id() == Pointer::id()).then_some(
            serde_json::from_slice::<Header>(&self.2).ok().filter(|h| h.protocol_id() != Pointer::id())?
        )
    }

    pub fn new(cache: &Cache, enc_key: &PathedKey, parent: &RecordPath, protocol: Protocol, header_data: Vec<u8>, index: u32) -> Result<Header, Error> {
        let parent_h = cache.get(parent)?;
        parent_h.1.validate_child(&protocol.id())?; 
        let children_keys = parent_h.0.children_keys()?;
        let header = Header(KeySet::new(
            children_keys.discover_child(index)?,
            children_keys.read_child(index)?,
            protocol.children.is_some().then_some(enc_key.children_keys(index)).transpose()?,
            protocol.delete.as_ref().map(|(d, _)| enc_key.child_keygen(index, *d)).transpose()?,
            protocol.others.iter().map(|(n, (k, _))|
                Ok((n.to_string(), enc_key.child_keygen(index, *k)?))
            ).collect::<Result<BTreeMap<String, Key>, secp256k1::Error>>()?
        ), protocol, header_data);
        header.validate()?;
        Ok(header)
    }

    pub fn new_root(root_enc_key: &PathedKey) -> Result<Header, secp256k1::Error> {
        let zero = SecretKey::from_slice(&[0; 32])?;
        Ok(Header(
            KeySet::new(zero, zero, Some(root_enc_key.root_children_keys()?), None, BTreeMap::default()), 
            Protocol::new("ROOT", Some(Children::new(vec![], true, true, true)), None, BTreeMap::default(), false),
            vec![]
        ))
    }
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Clone, Debug, Default, Hash)]
pub struct Permissions {
    ///Anyone can discover children, Anyone can read children
    pub children: Option<(bool, bool)>,
    ///Anyone can delete if deletes are possible
    pub delete: Option<bool>,
    ///Other keys that must be included and/or secret
    pub keys: BTreeMap<String, bool>,
}
impl Permissions {
    pub const fn new(children: Option<(bool, bool)>, delete: Option<bool>, keys: BTreeMap<String, bool>) -> Self {
        Permissions{children, delete, keys}
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct KeySet {
    pub discover: SecretKey,//Always parent childern.0/index
    pub read: SecretKey,//Always parent children.1/index
    pub children: Option<ChildrenKeys>,
    pub delete: Option<Key>,
    pub others: BTreeMap<String, Key>
}
impl Hash for KeySet {fn hash<H: Hasher>(&self, state: &mut H) {
    state.write(&self.discover.secret_bytes());
    state.write(&self.read.secret_bytes());
    self.children.hash(state);
    self.delete.hash(state);
    self.others.hash(state);
}}

impl KeySet {
    pub fn new(
        discover: SecretKey, read: SecretKey, children: Option<ChildrenKeys>, delete: Option<Key>, others: BTreeMap<String, Key>
    ) -> Self {KeySet{discover, read, children, delete, others}}

    fn children_keys(&self) -> Result<&ChildrenKeys, ValidationError> {
        self.children.as_ref().ok_or(ValidationError::ActionMismatch("Children".to_string()))
    }

    fn delete(&self) -> Result<&Key, ValidationError> {
        self.delete.as_ref().ok_or(ValidationError::ActionMismatch("Delete".to_string()))
    }

    pub fn get_other(&self, n: &str) -> Result<&Key, ValidationError> {
        self.others.get(n).ok_or(ValidationError::MissingPerms(format!("Key {n}")))
    }

    fn max(mut self, other: Self) -> Self {
        let mut others = other.others.into_iter().map(|(n, k)|
            (n.clone(), self.others.remove(&n).map(|k2| k.max(k2)).unwrap_or(k))
        ).collect::<BTreeMap<_, _>>()?;
        others.extend(self.others);
        Some(KeySet::new(
            self.discover, self.read,
            self.children.map(|c| c.max(other.children.unwrap())),
            self.delete.map(|d| d.max(other.delete.unwrap())),
            others
        ))
    }

    fn set(self, perms: &Permissions) -> Result<Self, ValidationError> {
        Ok(KeySet{
            discover: self.discover,
            read: self.read,
            delete: perms.delete.map(|d| self.delete.map(|d| d.set(perms.delete.unwrap())).transpose()?,
            children: self.children.map(|c| c.set(perms.children)).transpose()?,
            others: perms.keys.into_iter().map(|(n, p)|
                Ok((n.clone(), self.others.get(&n).and_then(|k| k.set(p)).ok_or(Error::MissingPerms(n))?))
            ).collect::<Result<BTreeMap<_,_>, ValidationError>>()?
        })
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
pub enum Key {Secret(SecretKey), Public(PublicKey)}
impl Hash for Key {fn hash<H: Hasher>(&self, state: &mut H) {self.public().hash(state);}}
impl PartialEq for Key {fn eq(&self, other: &Self) -> bool {self.public() == other.public()}}
impl Eq for Key {}
impl Key {
    pub fn public(&self) -> PublicKey {match self {
        Key::Secret(key) => key.easy_public_key(),
        Key::Public(key) => *key
    }}
    pub fn secret(&self) -> Option<SecretKey> {match self {
        Key::Secret(key) => Some(*key),
        Key::Public(_) => None 
    }}

    pub fn set(self, secret: bool) -> Option<Self> {match secret {
        false => Some(Key::Public(self.public())),
        true => self.secret().map(|s| Key::Secret(s)),
    }}

    pub fn max(self, other: Self) -> Self {
        match &self {
            Key::Secret(_) => self,
            Key::Public(_) => match other {
                Key::Secret(_) => other,
                Key::Public(_) => self
            }
        }
    }
}



#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ChildrenKeys(Key, Key);
impl ChildrenKeys {
    pub fn discover_child(&self, index: u32) -> Result<SecretKey, Error> {
        Ok(self.0.secret().ok_or(Error::MissingPerms("Discover Child".to_string()))?.easy_derive(&[index])?)
    }

    pub fn read_child(&self, index: u32) -> Result<SecretKey, Error> {
        Ok(self.1.secret().ok_or(Error::MissingPerms("Read Child".to_string()))?.easy_derive(&[index])?)
    }

    fn set(self, perms: (bool, bool)) -> Option<Self> {Some(ChildrenKeys(self.0.set(perms.0)?, self.1.set(perms.1)?))}
    fn max(mut self, other: Self) -> Self {ChildrenKeys(self.0.max(other.0), self.1.max(other.1))}
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct PathedKey(RecordPath, SecretKey);
impl AsRef<SecretKey> for PathedKey {fn as_ref(&self) -> &SecretKey {&self.1}}
impl PathedKey {
    pub fn new(path: RecordPath, key: SecretKey) -> Self {PathedKey(path, key)}
    pub fn path(&self) -> &RecordPath {&self.0}
    pub fn derive(&self, path: &RecordPath) -> Result<Self, secp256k1::Error> {
        match path.to_string().strip_prefix(&self.0.to_string()) {
            Some(stripped) => Ok(PathedKey(path.clone(), self.1.easy_derive(&stripped.bytes().map(|b| b as u32).collect::<Vec<_>>())?)),
            None => Err(secp256k1::Error::InvalidSecretKey)
        }
    }

    pub fn child_key(&self, index: u32, key: u32) -> Result<SecretKey, secp256k1::Error> {
        self.1.easy_derive(&[(u8::MAX as u32*2) + index, key])
    }

    pub fn child_keygen(&self, index: u32, key: KeyGen) -> Result<Key, secp256k1::Error> {Ok(match key {
        KeyGen::Static(key) => key,
        KeyGen::Derive(i) => Key::Secret(self.child_key(index, i)?)
    })}

    pub fn children_keys(&self, index: u32) -> Result<ChildrenKeys, secp256k1::Error> {
        Ok(ChildrenKeys(Key::Secret(self.child_key(0, 0)?), Key::Secret(self.child_key(0, 1)?)))
    }

    pub fn root_children_keys(&self) -> Result<ChildrenKeys, secp256k1::Error> {
        Ok(ChildrenKeys(
            Key::Secret(self.derive(&RecordPath::default())?.1.easy_derive(&[u8::MAX as u32])?),
            Key::Secret(self.derive(&RecordPath::default())?.1.easy_derive(&[u8::MAX as u32 + 1])?)
        ))
    }
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Clone, Debug, Hash, Copy)]
pub enum KeyGen{Static(Key), Derive(u32)}

#[derive(Clone, Debug)]
struct Pointer;
impl Pointer {
    fn get_protocol() -> Protocol {Protocol::new("Pointer", None, None, BTreeMap::new(), false)}
    fn id() -> Id {Self::get_protocol().id()}
}


//  fn discover(cache: &mut Cache, parent: &RecordPath, index: u32) -> Result<Option<(DateTime, Option<RecordPath>)>, Error> {
//      let parent_header = cache.get(&self.parent)?.clone();
//      let invalid_parent = ValidationError::InvalidParent(self.parent.to_string());
//      let childern_keys = parent_header.0.children.ok_or(invalid_parent)?;
//      let discover = children_keys.discver_child(self.index)?.ok_or(invalid_parent)?;
//      let read = children_keys.read_child(self.index)?;

//      let request: Option<(DateTime, Option<KeySigned<Vec<u8>>>)> = todo!();
//      
//      Ok(match (read, request) {
//          (_, None) => None,
//          (None, Some((date, _))) | (_, Some((date, None))) => Some((date, None)),
//          (Some(read), Some((date, Some(header)))) => Some((date, Header::decrypt(header, read).ok().and_then(|header| {
//              parent_header.1.validate_child(&header).ok()?;
//              let header = if let Some(header) = header.decode_pointer() {
//                  parent_header.1.validate_child(&header).ok().map(|_| header)?
//              } else {
//                  let protocol = &header.1;
//                  let my_header = Header::new(&cache, enc_key, parent, header.1.clone(), header.2.clone(), self.index).ok()?;
//                  if my_header.id() == header.id() {my_header} else {header}
//              };
//              let id = header.id();
//              cache.cache(header);
//              Some(self.parent.join(id))
//          })))
//      })
//  }

//  #[derive(Serialize, Deserialize)]
//  pub struct Create{
//      parent: RecordPath,
//      protocol: Protocol,
//      header_data: Vec<u8>,
//      index: u32,
//      perms: Permissions,
//      payload: Vec<u8>,
//      endpoint: Endpoint
//  }
//  impl Create {
//      pub fn new(parent: RecordPath, protocol: Protocol, header_data: Vec<u8>, index: u32, perms: Permissions, payload: Vec<u8>, endpoint: Endpoint) -> Self {
//          Create{parent, protocol, header_data, index, perms, payload, endpoint}
//      }
//  }
//  impl Command for Create {
//      type Output = Result<(RecordPath, Option<DateTime>), Error>;

//      async fn run(self, mut ctx: Context) -> Self::Output {
//          let o_header = Header::derive(
//              &*ctx.try_get_mut::<Cache>().await.ok_or(Error::MissingCache)?,
//              &self.parent, self.protocol, self.header_data, self.index
//          )?;
//          let header = o_header.clone().set(&self.perms)?;
//          let record = Record{header, payload: self.payload};
//          let discover = &record.header.0.discover;
//          let delete = record.header.0.delete.map(|d| d.public());
//          let payload = record.header.0.read.easy_public_key().easy_encrypt(serde_json::to_vec(&record)?)?;
//          let enc_header = record.header.0.read.easy_public_key().easy_encrypt(serde_json::to_vec(&record.header)?)?;
//          let path = self.parent.join(record.header.id());
//          let date = ctx.run(super::requests::CreatePrivate::new(discover, delete, enc_header, payload, self.endpoint)).await?;
//          ctx.try_get_mut::<Cache>().await.ok_or(Error::MissingCache)?.cache(o_header);
//          Ok((path.clone(), date))
//      }
//  }

//  #[derive(Serialize, Deserialize)]
//  pub struct Read{
//      path: RecordPath,
//      endpoint: Endpoint
//  }
//  impl Read {
//      pub fn new(path: RecordPath, endpoint: Endpoint) -> Self {
//          Read{path, endpoint}
//      }
//  }
//  impl Command for Read {
//      type Output = Result<Option<(DateTime, Option<Record>)>, Error>;

//      async fn run(self, mut ctx: Context) -> Self::Output {
//          let header = ctx.try_get_mut::<Cache>().await.ok_or(Error::MissingCache)?
//              .get(&self.path).ok_or(ValidationError::MissingRecord(self.path.to_string()))?.clone();
//          Ok(ctx.run(super::requests::ReadPrivate::new(&header.0.discover, self.endpoint)).await?.map(|(date, item)|
//              (date, item.and_then(|item| Record::from_item(item, *header.0.read).ok()).filter(|r| r.header == header))
//          ))
//      }
//  }

//  #[derive(Serialize, Deserialize)]
//  pub struct Delete{
//      path: RecordPath,
//      endpoint: Endpoint
//  }
//  impl Delete {
//      pub fn new(path: RecordPath, endpoint: Endpoint) -> Self {
//          Delete{path, endpoint}
//      }
//  }
//  impl Command for Delete {
//      type Output = Result<bool, Error>;

//      async fn run(self, mut ctx: Context) -> Self::Output {
//          let header = ctx.try_get_mut::<Cache>().await.ok_or(Error::MissingCache)?
//              .get(&self.path).ok_or(ValidationError::MissingRecord(self.path.to_string()))?.clone();
//          let discover = header.0.discover.easy_public_key();
//          let delete = header.0.delete.and_then(|d| d.secret()).ok_or(ValidationError::MissingPerms("Delete".to_string()))?;
//          Ok(ctx.run(super::requests::DeletePrivate::new(discover, &delete, self.endpoint)).await?.is_none())
//      }
//  }

//  #[derive(Serialize, Deserialize)]
//  pub struct Share{
//      secret: OrangeSecret,
//      recipient: OrangeName,
//      perms: Permissions,
//      path: RecordPath,
//      endpoint: Endpoint
//  }
//  impl Share {
//      pub fn new(secret: OrangeSecret, recipient: OrangeName, perms: Permissions, path: RecordPath, endpoint: Endpoint) -> Self {
//          Share{secret, recipient, perms, path, endpoint}
//      }
//  }
//  impl Command for Share {
//      type Output = Result<(), Error>;

//      async fn run(self, mut ctx: Context) -> Self::Output {
//          let header = ctx.try_get_mut::<Cache>().await.ok_or(Error::MissingCache)?
//              .get(&self.path).ok_or(ValidationError::MissingRecord(self.path.to_string()))?
//              .0.clone().set(&self.perms)?;
//          Ok(ctx.run(super::requests::CreateDM::new(self.secret, self.recipient, serde_json::to_vec(&header)?, self.endpoint)).await?)
//      }
//  }

//  #[derive(Serialize, Deserialize)]
//  pub struct Receive{
//      secret: OrangeSecret,
//      since: DateTime,
//      endpoint: Endpoint
//  }
//  impl Receive {
//      pub fn new(secret: OrangeSecret, since: DateTime, endpoint: Endpoint) -> Self {
//          Receive{secret, since, endpoint}
//      }
//  }
//  impl Command for Receive {
//      type Output = Result<Vec<(OrangeName, RecordPath)>, Error>;

//      async fn run(self, mut ctx: Context) -> Self::Output {
//          let sent = ctx.run(super::requests::ReadDM::new(self.secret, self.since, self.endpoint)).await?;
//          let mut cache = ctx.try_get_mut::<Cache>().await.ok_or(Error::MissingCache)?;
//          Ok(sent.into_iter().flat_map(|(s, p)| {
//              let header = serde_json::from_slice::<Header>(&p).ok()?;
//              header.validate().ok()?;
//              let id = Id::hash(&header);
//              let parent = vec![Pointer::id()];
//              let path = parent.join(id);
//              cache.cache(header);
//              Some((s, path))
//          }).collect())//TODO: Include who sent the record /fff/bob
//      }
//  }

//  #[derive(Serialize, Deserialize)]
//  pub struct CreatePointer{
//      parent: RecordPath,
//      record: RecordPath,
//      index: u32,
//      perms: Permissions,
//      endpoint: Endpoint
//  }
//  impl CreatePointer {
//      pub fn new(parent: RecordPath, record: RecordPath, index: u32, perms: Permissions, endpoint: Endpoint) -> Self {
//          CreatePointer{parent, record, index, perms, endpoint}
//      }
//  }
//  impl Command for CreatePointer {
//      type Output = Result<(RecordPath, Option<DateTime>), Error>;

//      async fn run(self, mut ctx: Context) -> Self::Output {
//          let cache = ctx.try_get_mut::<Cache>().await.ok_or(Error::MissingCache)?;
//          let record_header = cache 
//              .get(&self.record).ok_or(ValidationError::MissingRecord(self.record.to_string()))?.clone();
//          let o_header = Header::derive(
//              &cache, &self.parent, Pointer::get_protocol(), serde_json::to_vec(&record_header)?, self.index
//          )?;
//          drop(cache);

//          let header = o_header.clone().set(&self.perms)?;
//          let record = Record{header, payload: vec![]};
//          let discover = &record.header.0.discover;
//          let delete = record.header.0.delete.map(|d| d.public());
//          let payload = record.header.0.read.easy_public_key().easy_encrypt(serde_json::to_vec(&record)?)?;
//          let enc_header = record.header.0.read.easy_public_key().easy_encrypt(serde_json::to_vec(&record.header)?)?;
//          let path = self.parent.join(record.header.id());
//          let date = ctx.run(super::requests::CreatePrivate::new(discover, delete, enc_header, payload, self.endpoint)).await?;
//          ctx.try_get_mut::<Cache>().await.ok_or(Error::MissingCache)?.cache(o_header);
//          Ok((path.clone(), date))
//      }
//  }

pub type RecordPath = Vec<Id>;
pub trait RecordPathExt {
    fn parent(&self) -> Option<Self> where Self: Sized;
    fn last(&self) -> Id;
    fn join(&self, id: Id) -> Self where Self: Sized;
    fn to_string(&self) -> String;
}
impl RecordPathExt for RecordPath {
    fn parent(&self) -> Option<Self> {
        self.split_last().map(|t| t.1.to_vec())
    }
    fn last(&self) -> Id {<[Id]>::last(self).copied().unwrap_or(Id::MIN)}
    fn join(&self, id: Id) -> Self {[self.clone(), vec![id]].concat()}

    fn to_string(&self) -> String {
        format!("/{}", self.iter().map(|s| s.to_string()).collect::<Vec<_>>().join("/"))
    }
}
