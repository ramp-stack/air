use serde::{Serialize, Deserialize};
use orange_name::{Signed as OrangeSigned, Resolver, Secret, Name, secp256k1::{SecretKey, PublicKey}, Id};

use crate::server::{Error as PurserError, Command, Context, PurserRequest};

use std::collections::{BTreeMap, BTreeSet};
use std::hash::{Hasher, Hash};
use std::fmt::Debug;

use crate::{DateTime, now};

mod consensus;

#[derive(Debug)]
pub enum Error {
    MissingPerms(String),
    MissingFile(Id),
    InvalidParent(Id),
    InvalidFile(String),
    WrongSecretKey,
}
impl std::error::Error for Error {}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {write!(f, "{self:?}")}
}

#[derive(Serialize, Deserialize, Clone, Debug, Hash)]
pub struct DirectedItem(PublicKey, Vec<u8>);

impl DirectedItem {
    pub fn new(secret: &Secret, recipient: PublicKey, payload: Vec<u8>) -> Result<Self, orange_name::Error>{
        let signed = OrangeSigned::new(secret, &[], payload)?;
        Ok(DirectedItem(recipient, recipient.encrypt(serde_json::to_vec(&signed).unwrap()).unwrap()))
    }

    pub async fn verify(self, resolver: &mut Resolver, secret: &SecretKey) -> Result<(Name, Vec<u8>), orange_name::Error> {
        let signed = serde_json::from_slice::<OrangeSigned<Vec<u8>>>(&secret.decrypt(&self.1)?)
            .map_err(|_| secp256k1::Error::InvalidMessage)?;
        Ok((signed.signer(), signed.verify(resolver, None, None, None).await?))
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, Hash, PartialEq, Eq)]
pub struct PublicItem {
    pub tags: BTreeSet<String>,
    pub payload: Vec<u8>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Hash, PartialEq, Eq)]
pub enum Op {LS, LE, E, GE, GR}

#[derive(Serialize, Deserialize, Clone, Debug, Hash, PartialEq, Eq)]
pub struct Filter{
    pub id: Option<Id>,
    pub author: Option<Name>,
    pub tags: Option<BTreeSet<String>>,
    pub datetime: Option<(Op, DateTime)>
}
impl Filter {
    pub fn new(
        id: Option<Id>, author: Option<Name>, tags: Option<BTreeSet<String>>, datetime: Option<(Op, DateTime)>
    ) -> Self {
        Filter{id, author, tags, datetime}
    }

    pub fn filter(&self, oid: &Id, oauthor: &Name, oitem: &PublicItem, odatetime: &DateTime) -> bool {
        if let Some(id) = &self.id && id != oid {return false;}
        if let Some(author) = &self.author && author != oauthor {return false;}
        if let Some(tags) = &self.tags && !tags.is_subset(&oitem.tags) {return false;}
        if let Some((op, datetime)) = &self.datetime {
            match op {
                Op::LS if odatetime >= datetime => {return false;},
                Op::LE if odatetime > datetime => {return false;},
                Op::E if odatetime != datetime => {return false;},
                Op::GE if odatetime < datetime => {return false;},
                Op::GR if odatetime <= datetime => {return false;},
                _ => {}
            }
        }
        true
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, Hash)]
pub struct PrivateItem {
    pub discover: PublicKey,
    pub payload: Vec<u8>
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
pub enum Key {Secret(SecretKey), Public(PublicKey)}
impl Hash for Key {fn hash<H: Hasher>(&self, state: &mut H) {self.public().hash(state);}}
impl PartialEq for Key {fn eq(&self, other: &Self) -> bool {self.public() == other.public()}}
impl Eq for Key {}
impl Key {
    pub fn public(&self) -> PublicKey {match self {
        Key::Secret(key) => key.public_key(),
        Key::Public(key) => *key
    }}
    pub fn secret(&self) -> Option<SecretKey> {match self {
        Key::Secret(key) => Some(*key),
        Key::Public(_) => None 
    }}
}

type FileHeader = (SecretKey, Vec<Name>, Option<Children>);

#[derive(Default)]
pub struct FileCache(BTreeMap<Id, FileHeader>);
impl FileCache {
    pub fn get(&self, file: &Id) -> Option<&FileHeader> {self.0.get(file)}
    pub fn get_mut(&mut self, file: &Id) -> Option<&mut FileHeader> {self.0.get_mut(file)}

    pub fn cache(&mut self, file: &File) -> Result<(), Error> {
        self.0.insert(Id::hash(file), (file.key, file.servers.clone(), file.children.clone()));
        Ok(())
    }

    pub fn get_children(&self, parent: &Id) -> Result<&Children, Error> {
        self.get(parent).ok_or(Error::MissingFile(*parent))?.2
            .as_ref().ok_or(Error::InvalidParent(*parent))
    }
}

#[derive(Serialize, Deserialize, Clone, Hash)]
pub struct Children(Key, Vec<Name>);
impl Children {
    pub fn set_secret(&mut self, key: SecretKey) -> Result<(), Error> {
        (self.0.public() != key.public_key())
            .then(|| self.0 = Key::Secret(key))
            .ok_or(Error::WrongSecretKey)
    }

    pub fn get_key(&self, index: usize) -> Result<SecretKey, Error> {
        Ok(self.0.secret().ok_or(Error::MissingPerms("Child Key".to_string()))?.derive(&[index]))
    }
}

///File Actions:
///
///Discover: Derive index from the Children public key and read from all the servers (choose state
///based on majority)
///
///Read: Read key from all the servers (choose state based on majority)
///
///Create: Send the file to each of the servers (Require successful response from majority)
///
///Update/Delete: Not Available 
#[derive(Serialize, Deserialize, Clone, Hash)]
pub struct File {
    pub key: SecretKey,
    pub servers: Vec<Name>,
    pub timestamp: DateTime,
    pub payload: Vec<u8>,
    pub children: Option<Children>,
}
impl File {
    pub fn new(cache: &FileCache, parent: &Id, index: usize, payload: Vec<u8>, children: Option<Children>) -> Result<Self, Error> {
        let pchildren = cache.get_children(parent)?;
        Ok(File{
            key: pchildren.get_key(index)?,
            servers: pchildren.1.clone(),
            timestamp: now(),
            payload,
            children
        })
    }
}

pub use consensus::CreateFile;

#[derive(Serialize, Deserialize)]
pub struct ReadFile(SecretKey, Name, Vec<Name>, Id);
impl ReadFile {
    pub fn new(cache: &FileCache, file: &Id) -> Result<Self, Error> {
        let (key, servers, _) = cache.get(file).ok_or(Error::MissingFile(*file))?;
        let mut servers = servers.clone();
        let first_server = servers.pop().ok_or(Error::InvalidFile("No Servers".to_string()))?;
        Ok(ReadFile(*key, first_server, servers, *file))
    }
}
impl Command<PurserRequest> for ReadFile {
    type Output = Result<Option<File>, PurserError>;

    async fn run(self, ctx: Context) -> Self::Output {
        consensus::ReadFile(self.0, self.1, self.2, Some(self.3)).run(ctx).await
    }
}

#[derive(Serialize, Deserialize)]
pub struct DiscoverFile(SecretKey, Name, Vec<Name>);
impl DiscoverFile {
    pub fn new(cache: &FileCache, parent: &Id, index: usize) -> Result<Self, Error> {
        let children = cache.get_children(parent)?;
        let mut servers = children.1.clone();
        let key = children.get_key(index)?;
        let first_server = servers.pop().ok_or(Error::InvalidFile("No Servers".to_string()))?;
        Ok(DiscoverFile(key, first_server, servers))
    }
}
impl Command<PurserRequest> for DiscoverFile {
    type Output = Result<Option<File>, PurserError>;

    async fn run(self, ctx: Context) -> Self::Output {
        consensus::ReadFile(self.0, self.1, self.2, None).run(ctx).await
    }
}
