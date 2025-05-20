use easy_secp256k1::{EasySecretKey, EasyHash, Hashable};
use secp256k1::SecretKey;
use dyn_hash::{DynHash, hash_trait_object};
use dyn_eq::{DynEq, eq_trait_object};
use chrono::Utc;
use serde::{Serialize, Deserialize};
use std::collections::{HashMap, HashSet, BTreeMap, VecDeque};
use std::collections::hash_map::Entry;
use std::hash::{Hasher, Hash};
use std::ops::Deref;
use std::fmt::Debug;
use std::any::Any;

use super::records::{self, KeySet, Record, Id, Key, Error, ValidationError};

#[derive(Default, Debug, Clone, PartialEq, Eq, Hash, Ord, PartialOrd)]
#[derive(serde_with::SerializeDisplay)]
#[derive(serde_with::DeserializeFromStr)]
pub struct RecordPath(Vec<Id>);
impl RecordPath {
    pub fn parent(&self) -> Option<Self> {
        self.0.split_last().map(|t| RecordPath(t.1.to_vec()))
    }
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
    pub fn new_root(key: SecretKey) -> Self {PathedKey(RecordPath(Vec::new()), key)}
    pub fn path(&self) -> &RecordPath {&self.0}
    pub fn derive(&self, path: &RecordPath) -> Result<Self, ValidationError> {
        match path.to_string().strip_prefix(&self.0.to_string()) {
            Some(stripped) => Ok(PathedKey(path.clone(), self.1.easy_derive(&stripped.bytes().map(|b| u8::MAX as u32 + b as u32).collect::<Vec<_>>()).unwrap())),
            None => Err(ValidationError::MissingPerms(path.to_string()))
        }
    }
    pub fn index(&self, index: u32) -> Result<SecretKey, ValidationError> {
        Ok(self.1.easy_derive(&[(u8::MAX as u32 * 2) + index])?)
    }
}

pub struct Cache(BTreeMap<Id, (KeySet, Box<dyn Protocol>)>);
impl Cache {
    pub fn get(&self, id: &Id) -> Option<&(KeySet, Box<dyn Protocol>)> {self.0.get(id)}
    pub fn set(&mut self, val: (KeySet, Box<dyn Protocol>)) {self.0.insert(Id::from(&val), val);}
}

pub trait Protocol: DynHash {
    fn child_set(&self, cache: &mut Cache, key: &PathedKey, index: u32) -> Result<KeySet, ValidationError>;
}
hash_trait_object!(Protocol);

pub struct RoomProtocol;
impl Hash for RoomProtocol {fn hash<H: Hasher>(&self, state: &mut H) {state.write(b"RoomProtocol");}}
impl Protocol for RoomProtocol {
    fn new_set(&self, cache: &mut Cache, key: &PathedKey, index: u32) -> Result<KeySet, ValidationError> {
        let parent = cache.get(key.path().parent().unwrap().last().unwrap()).unwrap();
        let key = key.index(index)?;
        Ok(KeySet {
            discover: parent.children.and_then(|c| c.secret()).unwrap().easy_derive(&[index])?,
            read: Key::Secret(key.easy_derive(&[1])?),
            delete: None,
            children: Some(Key::Secret(key.easy_derive(&[2])?)),
            other: BTreeMap::from([
                ("read_child".to_string(), Key::Secret(key.easy_derive(&[3])?))
                (hex::encode(EasyHash::core_hash(MessageProtocol)?), Key::Secret(key.easy_derive(&[3])?))
            ])
        })
    }
}

///Requires: 
///1. ../"read_child"
pub struct MessageProtocol;
impl Hash for MessageProtocol {fn hash<H: Hasher>(&self, state: &mut H) {state.write(b"MessageProtocol");}}
impl Protocol for MessageProtocol {
    fn new_set(&self, cache: &mut Cache, key: &PathedKey, index: u32) -> Result<KeySet, ValidationError> {
        let parent = cache.get(key.path().parent().unwrap().last().unwrap()).unwrap();
        Ok(KeySet {
            discover: parent.other.get(&hex::encode(EasyHash::core_hash(MessageProtocol)?)).unwrap().easy_derive(&[index])?,
            read: parent.other.get("read_child").unwrap().clone(),
            delete: Some(Key::Secret(key.index(index)?.easy_derive(&[0])?)),
            children: None,
            other: BTreeMap::new()
        })
    }

    fn validate(&self, cache: &mut Cache, parent: &RecordPath, keyset: &KeySet, index: u32) -> Result<(), ValidationError> {
        let parent = cache.get(parent.unwrap().last().unwrap()).unwrap();
        if keyset.discover != parent.other.get(&hex::encode(EasyHash::core_hash(MessageProtocol)?)).unwrap().easy_derive(&[index])? ||
           keyset.read != parent.other.get("read_child").unwrap().clone() ||
           keyset.delete.is_none() {
            Err(ValidationError::DifferentKeys)
        } else {Ok(())}
    }
}

use super::records::Conflict;
use crate::server::{Request, ChandlerRequest, ChandlerResponse, PurserError};

#[derive(Clone, Debug, Hash)]
pub struct Create(records::Create);
impl AsRef<ChandlerRequest> for Create {fn as_ref(&self) -> &ChandlerRequest {self.0.as_ref()}}
impl Create {
    pub fn new(cache: &mut Cache, key: &PathedKey, protocol: &dyn Protocol, payload: Vec<u8>) -> Result<Self, ValidationError> {
        protocol.child_set(cache, key, 
        //let (keyset, protocol) = cache.get(key.path()).unwrap();

        todo!()
      //cache.get(parent).unwrap(). 
      //let discover = &record.keys.discover;
      //let delete = record.keys.delete.clone().map(|d| d.public());
      //let payload = record.keys.read.public().easy_encrypt(serde_json::to_vec(&record)?)?;
      //Ok(Create(requests::CreatePrivate::new(discover, delete, payload), record.keys.clone()))
    }
}
impl Request for Create {
    type Output = Result<Option<Conflict>, Error>;

    fn process(self, response: Result<ChandlerResponse, PurserError>) -> Self::Output {
        todo!()
      //match self.0.process(response)? {
      //  //Some(item) => match Record::from_item(&item, &self.1) {
      //  //    Ok(Some(record)) => Ok(Some(Conflict::Record(Box::new(record)))),
      //  //    Ok(None) => Ok(Some(Conflict::Encrypted(item.payload))),
      //  //    Err(e) => Ok(Some(Conflict::Corrupted(e)))
      //  //},
      //  //None => Ok(None)
      //}
    }
}

//  #[derive(Clone, Debug, Hash)]
//  pub struct Read(requests::ReadPrivate, KeySet);
//  impl AsRef<ChandlerRequest> for Read {fn as_ref(&self) -> &ChandlerRequest {self.0.as_ref()}}
//  impl Read {
//      pub fn new(keys: KeySet) -> Result<Self, ValidationError> {
//          if matches!(keys.read, Key::Public(_)) {
//              return Err(ValidationError::MissingPerms("Read".to_string()));
//          }
//          Ok(Read(requests::ReadPrivate::new(&keys.discover), keys))
//      }
//  }
//  impl RequestTrait for Read {
//      type Output = Result<Option<Record>, Error>;
//      fn process(self, response: Result<ChandlerResponse, PurserError>) -> Self::Output {
//          self.0.process(response)?.map(|item|
//              Record::from_item(&item, &self.1).map(|r| r.unwrap()).map_err(Error::CorruptedRecord)
//          ).transpose()
//      }
//  }

//  #[derive(Clone, Debug, Hash)]
//  pub struct Update(requests::UpdatePrivate);
//  impl AsRef<ChandlerRequest> for Update {fn as_ref(&self) -> &ChandlerRequest {self.0.as_ref()}}
//  impl Update {
//      pub fn new(record: &Record, keyset: &KeySet) -> Result<Self, ValidationError> {
//          let discover = &record.keys.discover;
//          let delete = keyset.delete.clone().and_then(|d| d.secret()).ok_or(ValidationError::MissingPerms("Delete".to_string()))?;
//          let payload = record.keys.read.public().easy_encrypt(serde_json::to_vec(&record)?)?;
//          Ok(Update(requests::UpdatePrivate::new(discover, &delete, payload)))
//      }
//  }
//  impl RequestTrait for Update {
//      type Output = Result<(), Error>;
//      fn process(self, response: Result<ChandlerResponse, PurserError>) -> Self::Output {
//          Ok(self.0.process(response)?)
//      }
//  }

//  #[derive(Clone, Debug, Hash)]
//  pub struct Delete(requests::DeletePrivate);
//  impl AsRef<ChandlerRequest> for Delete {fn as_ref(&self) -> &ChandlerRequest {self.0.as_ref()}}
//  impl Delete {
//      pub fn new(keys: &KeySet) -> Result<Self, Error> {
//          let delete = keys.delete.as_ref().and_then(|d| d.secret()).ok_or(ValidationError::MissingPerms("Delete".to_string()))?;
//          Ok(Delete(requests::DeletePrivate::new(keys.discover.easy_public_key(), &delete)))

//      }
//  }
//  impl RequestTrait for Delete {
//      type Output = Result<(), Error>;
//      fn process(self, response: Result<ChandlerResponse, PurserError>) -> Self::Output {
//          Ok(self.0.process(response)?)
//      }
//  }
