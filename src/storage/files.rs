use serde::{Serialize, Deserialize};
use orange_name::{Secret, Name, secp256k1::{SecretKey, PublicKey, Signed as KeySigned}, Id};

use crate::server::{Error as PurserError, Command, Context, PurserRequest};

use std::collections::BTreeMap;
use std::path::{PathBuf, Path};
use std::hash::{Hasher, Hash};
use std::fmt::Debug;

use crate::{DateTime, now};

//mod consensus;

#[derive(Debug)]
pub enum Error {
    MissingPerms(PathBuf),
    MissingFile(PathBuf),
    InvalidParent(PathBuf),
    InvalidFile(PathBuf),
}
impl std::error::Error for Error {}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {write!(f, "{self:?}")}
}

#[derive(Debug)]
pub enum RequestError {
    FileError(Error),
    PurserError(PurserError)
}
impl std::error::Error for RequestError {}
impl std::fmt::Display for RequestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {write!(f, "{self:?}")}
}
impl From<Error> for RequestError {fn from(e: Error) -> Self {Self::FileError(e)}}
impl From<PurserError> for RequestError {fn from(e: PurserError) -> Self {Self::PurserError(e)}}


#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
pub enum Key {Secret(SecretKey), Public(PublicKey)}
impl Hash for Key {fn hash<H: Hasher>(&self, state: &mut H) {self.public_key().hash(state);}}
impl PartialEq for Key {fn eq(&self, other: &Self) -> bool {self.public_key() == other.public_key()}}
impl Eq for Key {}
impl Key {
    pub fn public_key(&self) -> PublicKey {match self {
        Key::Secret(key) => key.public_key(),
        Key::Public(key) => *key
    }}
    pub fn secret_key(&self) -> Option<SecretKey> {match self {
        Key::Secret(key) => Some(*key),
        Key::Public(_) => None 
    }}
}

pub trait FilePath {
    fn to_ids(&self) -> Vec<Id>;
    fn first(&self) -> Option<String>;
    fn last(&self) -> String;
}

impl<P: AsRef<Path>> FilePath for P {
    fn to_ids(&self) -> Vec<Id> {
        self.as_ref().components().map(|c|
            Id::hash(&c.as_os_str().to_string_lossy().to_string())
        ).collect::<Vec<_>>()
    }

    fn first(&self) -> Option<String> {
        self.as_ref().components().next().map(|s| s.as_os_str().to_string_lossy().to_string())
    }

    fn last(&self) -> String {
        self.as_ref().file_name().map(|n|
            n.to_string_lossy().to_string()
        ).unwrap_or("".to_string())
    }
}

#[derive(Clone, Hash)]
#[derive(serde_with::SerializeDisplay)]
#[derive(serde_with::DeserializeFromStr)]
pub struct Serialized(String);
impl std::fmt::Display for Serialized {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}
impl std::str::FromStr for Serialized {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Serialized(s.to_string()))
    }
}

///The minimum amount of information on a file required to read and verify
#[derive(Serialize, Deserialize, Debug, Clone, Hash, PartialEq, Eq)]
pub struct Pointer {
    pub id: Id,
    pub key: Key,
    pub servers: Vec<Name>
}


//  #[derive(Serialize, Deserialize, Default, Clone, Debug)]
//  pub struct RecordCache(Option<(PathBuf, RecordTree)>);//last item in pathBuf matches Record Tree Record Name
//  impl RecordCache {
//      
//  }
//  impl FileNode {
//      pub fn get<P: AsRef<Path>>(&self, path: P) -> Option<&FileNode> {
//          if path.as_ref() == PathBuf::new() {Some(self)} else {
//              self.children.1.get(path.first().unwrap()).and_then(|node| node.get(path))
//          }
//      }

//      pub fn get_mut<P: AsRef<Path>>(&mut self, path: P) -> Option<&mut FileNode> {
//          if path.as_ref() == PathBuf::new() {Some(self)} else {
//              self.children.1.get_mut(
//                  path.as_ref().components().next().unwrap().as_os_str().to_string_lossy().as_ref()
//              ).and_then(|node| node.get_mut(path))
//          }
//      }
//  }

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct CachedFile {
    key: SecretKey,
    name: String,
    servers: Vec<Name>,
    children: Option<Key>,//(key, latest_index, children)
}

#[derive(Serialize, Deserialize, Default, Debug, Clone)]
pub struct FileCache(BTreeMap<Vec<Id>, CachedFile>);
impl FileCache {
    pub fn is_empty(&self) -> bool {self.0.is_empty()}

    pub fn get<P: AsRef<Path>>(&self, path: P) -> Option<&CachedFile> {
        self.0.get(&path.to_ids())
    }

    pub fn get_mut<P: AsRef<Path>>(&mut self, path: P) -> Option<&mut CachedFile> {
        self.0.get_mut(&path.to_ids())
    }

    pub fn cache<T>(&mut self, path: PathBuf, file: &File<T>) -> Result<(), CachedFile> {
        //TODO: Merge with existing cache data
        self.0.insert(path.to_ids(), CachedFile{
            key: file.key,
            name: file.name.clone(),
            servers: file.servers.clone(),
            children: file.children,
        });
        Ok(())
    }

  //pub fn get_children(&self, parent: &PathBuf) -> Result<&Header, Error> {
  //    self.get(parent).ok_or(Error::MissingFile(parent.to_vec()))?.1
  //        .as_ref().ok_or(Error::InvalidParent(parent.to_vec()))
  //}
}



// bob creates file: bob/'/children/cat -> file
// bob deligates   : bob/cat/'/key -> ^
//
//
// alice gets bobs : alice/'/children/cat -> ^
// alice deligates : alice/cat/'/key -> ^ 

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct File<Payload> {
    pub key: SecretKey,
    pub name: String,
    pub servers: Vec<Name>,
    pub payload: Payload,
    pub datetime: DateTime,
    pub children: Option<Key>,
}

impl File<()> {
    pub fn root(secret: &Secret, servers: Vec<Name>) -> Result<File<()>, orange_name::Error> {
        let files = secret.get_hardend(None, &[], "files")?;
        Ok(File{
            key: files.derive(&["key"]),
            name: "".to_string(),
            servers: servers.clone(),
            payload: (),
            datetime: DateTime::UNIX_EPOCH,
            children: Some(Key::Secret(files.derive(&["children"])))
        })
    }
}

impl<T: Serialize + Hash> Hash for File<T> {
    fn hash<H: Hasher>(&self, hasher: &mut H) {
        self.key.hash(hasher);
        self.servers.hash(hasher);
        //Reserializing has no effect on already serialized files
        Serialized(serde_json::to_string(&self.payload).unwrap()).hash(hasher);
        self.datetime.hash(hasher);
        self.children.hash(hasher);
    }
}

impl<T: Serialize + for<'a> Deserialize<'a> + Hash + 'static> File<T> {
    pub fn new(
        secret: &Secret, mut path: PathBuf, index: usize, servers: Vec<Name>, payload: T, children: bool
    ) -> Result<Self, Error> {
        let files_key = secret.get_hardend(None, &path.to_ids(), "files")
            .or(Err(Error::MissingPerms(path.clone())))?;
        Ok(File{
            key: files_key.derive(&["key"]).derive(&[index]),
            name: path.last(),
            servers,
            payload,
            datetime: now(),
            children: children.then_some(Key::Secret(files_key.derive(&["children"])))
        })
    }

    pub fn pointer(&self) -> Pointer {Pointer{
        id: self.id(),
        key: Key::Secret(self.key),
        servers: self.servers.clone(),
    }}

    pub fn id(&self) -> Id {Id::hash(self)}

    pub fn serialize_payload(self) -> Result<File<Serialized>, serde_json::Error> {
        Ok(File{
            key: self.key,
            name: self.name,
            servers: self.servers,
            //Reserializing has no effect on already serialized files
            payload: Serialized(serde_json::to_string(&self.payload)?),
            datetime: self.datetime,
            children: self.children
        })
    }
}

impl File<Serialized> {
    pub fn deserialize_payload<T: Serialize + for<'a> Deserialize<'a>>(self) -> Result<File<T>, serde_json::Error> {
        Ok(File{
            key: self.key,
            name: self.name,
            servers: self.servers,
            payload: serde_json::from_str(&self.payload.0)?,
            datetime: self.datetime,
            children: self.children
        })
    }
}
