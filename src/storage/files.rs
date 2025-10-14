use serde::{Serialize, Deserialize};
use orange_name::{Secret, Name, secp256k1::{SecretKey, PublicKey, Signed as KeySigned}, Id};

use crate::server::{Error as PurserError, Command, Context, PurserRequest};

use std::collections::BTreeMap;
use std::path::{PathBuf, Path};
use std::hash::{Hasher, Hash};
use std::fmt::Debug;

use crate::{DateTime, now};

use super::channels::{Channel};
//mod consensus;


#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Hash)]
pub struct Permission(Actor, Action);

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Hash)]
pub struct Children(Vec<Name>, Vec<Id>);

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Hash)]
pub enum Actor {
    Author(usize),
    Anyone(usize),
    Group(usize, String),
    Name(Name),
    All(Vec<Actor>),
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Hash)]
pub enum Action {Create, Update, Delete, Read}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Protocol(PathBuf, Id, String, Children, Vec<Permission>, BTreeMap<String, Vec<Name>>);
impl Protocol {
    pub fn id(&self) -> Id {self.1}
    pub fn name(&self) -> &str {&self.2}
    pub fn new(name: &str, children: Children, permissions: Vec<Permission>, groups: BTreeMap<String, Vec<Name>>) -> Self {
        let name = name.to_string();
        let id = Id::hash(&(&name, &children, &permissions, &groups));
        Protocol(PathBuf::from(id.to_string()), id, name, children, permissions, groups)
    }

    pub fn root(servers: Vec<Name>) -> Self {
        Protocol::new("root", Children(servers.clone(), vec![]), vec![
            Permission(Actor::Anyone(0), Action::Create),
            Permission(Actor::Author(0), Action::Read),//Author auto attest to the content
            Permission(Actor::Author(0), Action::Update),
            Permission(Actor::Author(0), Action::Delete),
        ], BTreeMap::default())
    }

    fn protocol_folder(servers: Vec<Name>, protocol_id: Id) -> Self {
        Protocol::new("protocol_folder", Children(servers, vec![protocol_id]), vec![
            Permission(Actor::Author(1), Action::Create),
            Permission(Actor::Author(0), Action::Read),//Author auto attest to the content
            Permission(Actor::Author(0), Action::Update),
            Permission(Actor::Author(0), Action::Delete),
        ], BTreeMap::default())
    }
}
impl Hash for Protocol {fn hash<H: Hasher>(&self, state: &mut H) {
    self.2.hash(state); self.3.hash(state); self.4.hash(state); self.5.hash(state);
}}
impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {write!(f, "{}", self.1)}
}
impl AsRef<Path> for Protocol {fn as_ref(&self) -> &Path {&self.0}}


pub struct Validation(Vec<PrivateItem>);
impl Command for Validation {
    type Output = Vec<Option<FileHeader>>;
    async fn run(ctx: Context) -> Self::Output {
    }
}

impl channel::Validation<FileHeader> for Validation {
    fn id(&self) -> Id {Id::hash(b"File Validation")}

    fn validate(&self, items: Vec<PrivateItem>) -> Box<dyn Command<Output = Vec<Option<FileHeader>>>> {
        Box::new(Validation(items))
    }
}

pub enum Header {
    Create(Protocol, Vec<u8>),//Update
    Delete
}

pub struct File {//Cached
    channel: Channel<Header>,
    latest_version: usize,
    payload: Id//channel Id
}

pub struct Create(PathBuf, Protocol, Vec<u8>);

pub struct Read(PathBuf);

pub struct Update(PathBuf, Protocol, Vec<u8>);

pub struct Delete(PathBuf);














//  #[derive(Clone, Debug)]
//  pub enum Error {
//      MissingPerms(PathBuf),
//      MissingFile(PathBuf),
//      InvalidParent(PathBuf),
//      ConflictingFile(PathBuf),
//  }
//  impl Error {
//      pub fn prefix(mut self, prefix: PathBuf) -> Self {
//          match &mut self {
//              Self::MissingPerms(p) | Self::MissingFile(p) |
//              Self::InvalidParent(p) | Self::ConflictingFile(p) => 
//              *p = prefix.join(p.clone())
//          }
//          self
//      }
//  }
//  impl std::error::Error for Error {}
//  impl std::fmt::Display for Error {
//      fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {write!(f, "{self:?}")}
//  }

//  #[derive(Debug)]
//  pub enum RequestError {
//      FileError(Error),
//      PurserError(PurserError)
//  }
//  impl std::error::Error for RequestError {}
//  impl std::fmt::Display for RequestError {
//      fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {write!(f, "{self:?}")}
//  }
//  impl From<Error> for RequestError {fn from(e: Error) -> Self {Self::FileError(e)}}
//  impl From<PurserError> for RequestError {fn from(e: PurserError) -> Self {Self::PurserError(e)}}


//  pub trait FilePath {
//      fn to_ids(&self) -> Vec<Id>;
//      fn first(&self) -> Option<String>;
//      fn last(&self) -> String;
//  }

//  impl<P: AsRef<Path>> FilePath for P {
//      fn to_ids(&self) -> Vec<Id> {
//          self.as_ref().components().map(|c|
//              Id::hash(&c.as_os_str().to_string_lossy().to_string())
//          ).collect::<Vec<_>>()
//      }

//      fn first(&self) -> Option<String> {
//          self.as_ref().components().next().map(|s| s.as_os_str().to_string_lossy().to_string())
//      }

//      fn last(&self) -> String {
//          self.as_ref().file_name().map(|n|
//              n.to_string_lossy().to_string()
//          ).unwrap_or("".to_string())
//      }
//  }

//  //  #[derive(Clone, Hash)]
//  //  #[derive(serde_with::SerializeDisplay)]
//  //  #[derive(serde_with::DeserializeFromStr)]
//  //  pub struct Serialized(String);
//  //  impl std::fmt::Display for Serialized {
//  //      fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
//  //          write!(f, "{}", self.0)
//  //      }
//  //  }
//  //  impl std::str::FromStr for Serialized {
//  //      type Err = String;
//  //      fn from_str(s: &str) -> Result<Self, Self::Err> {
//  //          Ok(Serialized(s.to_string()))
//  //      }
//  //  }

//  //  ///The minimum amount of information on a file required to read and verify
//  //  #[derive(Serialize, Deserialize, Debug, Clone, Hash, PartialEq, Eq)]
//  //  pub struct Pointer {
//  //      pub id: Id,
//  //      pub key: Key,
//  //      pub servers: Vec<Name>
//  //  }

//  //How do I determian what the children key is???
//  //Has to be used to hid children from thoes without permission
//  //If permission for a channels children is revoked
//  #[derive(Serialize, Deserialize, Clone, Debug)]
//  pub struct File {
//      channel: Channel,//Can be used to receive updated file versions
//      //In order to know the children the file has to be read????
//      //payload: Vec<u8>,
//      children: Option<Key>//Not a good thing to make public since many situations allow discovering one
//                           //child but not another, Which means even the header cannot be read by
//                           //anyone with the parent
//      //parent servers are to be used
//      //pointers are required to change the servers in use for a file
//  }
//  //Is there every a situation where I cannot read a file but I can read or modify its children? NO
//  //
//  //Therefore if read access is revoked on a file its children need to change
//  //But the path and signature path does not need to change


//  //In order to hit a wall as far as whats allowed
//  //I must read the header of all the child headers
//  //and validate that I do not have read permission
//  //
//  //Which means someone without read access gets to know:
//  // 1. The permissions for the file(who can do what to it)
//  // 2. The namespace of the child
//  // 3. The date it was created

//  #[derive(Serialize, Deserialize, Clone, Debug)]
//  pub struct Children {
//      key: Key,
//      children: BTreeMap<String, Self>
//  }

//  #[derive(Serialize, Deserialize, Clone, Debug)]
//  pub struct Version {
//      payload: Id,
//      children: Option<Children>
//  }

//  //  impl Version {
//  //      pub fn merge_versions(mut m: BTreeMap<String, Self>, om: BTreeMap<String, Self>) -> Result<BTreeMap<String, Self>, Error> {
//  //          for (n, f) in om { match m.get_mut(&n) {
//  //              Some(file) => {*file = file.clone().merge(f).map_err(|e| e.prefix(PathBuf::from(n)))?},
//  //              None => {m.insert(n, f);}
//  //          }}
//  //          Ok(m)
//  //      }

//  //      pub fn merge_children(mut m: BTreeMap<String, Self>, om: BTreeMap<String, Self>) -> Result<BTreeMap<String, Self>, Error> {
//  //          for (n, f) in om { match m.get_mut(&n) {
//  //              Some(file) => {*file = file.clone().merge(f).map_err(|e| e.prefix(PathBuf::from(n)))?},
//  //              None => {m.insert(n, f);}
//  //          }}
//  //          Ok(m)
//  //      }
//  //  }

//  #[derive(Serialize, Deserialize, Clone, Debug)]
//  pub struct CachedFile {
//      channel: Channel,
//      //If new versions of the file are accepted from the channel above they must have the same child
//      //key as the first valid version
//      versions: Vec<Version>//PayloadId, ChildKey, Children
//  }
//  //  impl CachedFile {
//  //      pub fn merge(self, other: Self) -> Result<Self, Error> {
//  //          let error = Error::ConflictingFile(PathBuf::new());
//  //          if self.children.is_some() != other.children.is_some() {Err(error.clone())?}
//  //          Ok(CachedFile{
//  //              channel: self.channel.merge(other.channel).ok_or(error.clone())?,
//  //              children: self.children.map(|(c, m)| {
//  //                  let (oc, om) = other.children.unwrap();
//  //                  Ok((oc.merge(c).ok_or(error)?, Self::merge_children(m, om)?))
//  //              }).transpose()?
//  //          })
//  //      }

//  //      pub fn merge_children(mut m: BTreeMap<String, Self>, om: BTreeMap<String, Self>) -> Result<BTreeMap<String, Self>, Error> {
//  //          for (n, f) in om { match m.get_mut(&n) {
//  //              Some(file) => {*file = file.clone().merge(f).map_err(|e| e.prefix(PathBuf::from(n)))?},
//  //              None => {m.insert(n, f);}
//  //          }}
//  //          Ok(m)
//  //      }

//  //      pub fn get_mut<P: AsRef<Path>>(&mut self, path: P) -> Result<Option<&mut Self>, Error> {
//  //          let ip = Error::InvalidParent(PathBuf::new());
//  //          Ok(match path.first() {
//  //              Some(child) => match self.children.as_mut().ok_or(ip)?.1.get_mut(&child) {
//  //                  Some(c) => c.get_mut(path.as_ref().strip_prefix(child).unwrap())?,
//  //                  None => None
//  //              },
//  //              None => Some(self)
//  //          })
//  //      }

//  //      ///Can only merge a child in if the child or the direct parent of the child already exists
//  //      ///path should be stripped from its parent prefix
//  //      pub fn merge_child(&mut self, mut path: PathBuf, file: Self) -> Result<(), Error> {
//  //          if let Some(child) = self.get_mut(&path)? {
//  //              *child = child.clone().merge(file)?;
//  //          } else {
//  //              //If parent.get_mut(prefix) returned None prefix.parent is not None
//  //              let name = path.last();
//  //              path.pop();
//  //              self.get_mut(&path)?
//  //                  .ok_or(Error::MissingFile(path.clone()))?
//  //                  .children.as_mut()
//  //                  .ok_or(Error::InvalidParent(path))?.1
//  //                  .insert(name, file);
//  //          }
//  //          Ok(())
//  //      }
//  //  }

//  //Paths are /Protocol_Id/Item_Id.v/name.v/name.v/etc
//  //Keys  are /Protocol_Id/item_id/name/name/etc
//  //Item_Id is Hash(Channel)
//  //Channel key comes from author/Protocol/Name
//  //Protocol folders also have a version but only used by the author never shared
//  //The protocol will need to be rolled when the encryption key is comprimised

//  #[derive(Serialize, Deserialize, Default, Debug, Clone)]
//  pub struct FileCache(PathBuf, CachedFile);
//  impl FileCache {
//    //pub fn is_empty(&self) -> bool {self.0.is_empty()}

//    //pub fn get<P: AsRef<Path>>(&self, path: P) -> Option<&CachedFile> {
//    //    self.0.get(&path.to_ids())
//    //}

//    //pub fn get_mut<P: AsRef<Path>>(&mut self, path: P) -> Option<&mut CachedFile> {
//    //    self.0.get_mut(&path.to_ids())
//    //}

//  //  pub fn cache<T>(&mut self, path: PathBuf, mut file: CachedFile) -> Result<(), Error> {
//  //      if let Some((parent, prefix)) = self.0.iter_mut().find_map(|(parent_path, parent)|
//  //          path.strip_prefix(parent_path).map(|prefix| (parent, prefix)).ok()
//  //      ) {
//  //          parent.merge_child(prefix.to_path_buf(), file)?;
//  //      } else {
//  //          let children = self.0.iter().filter_map(|(child, _)|
//  //              child.strip_prefix(&path).map(|pre| (pre.to_path_buf(), child.clone())).ok()
//  //          ).collect::<Vec<_>>();
//  //          for (prefix, child_path) in children {
//  //              file.merge_child(prefix, self.0.remove(&child_path).unwrap()).map_err(|e| e.prefix(path.clone()))?;
//  //          }
//  //          self.0.insert(path, file);
//  //      }
//  //      Ok(())
//  //  }

//    //pub fn get_children(&self, parent: &PathBuf) -> Result<&Header, Error> {
//    //    self.get(parent).ok_or(Error::MissingFile(parent.to_vec()))?.1
//    //        .as_ref().ok_or(Error::InvalidParent(parent.to_vec()))
//    //}
//  }



//  // bob creates file: bob/'/children/cat -> file
//  // bob deligates   : bob/cat/'/key -> ^
//  //
//  //
//  // alice gets bobs : alice/'/children/cat -> ^
//  // alice deligates : alice/cat/'/key -> ^ 

//  //  #[derive(Serialize, Deserialize, Debug, Clone)]
//  //  pub struct File<Payload> {
//  //      pub key: SecretKey,
//  //      pub name: String,
//  //      pub servers: Vec<Name>,
//  //      pub payload: Payload,
//  //      pub datetime: DateTime,
//  //      pub children: Option<Key>,
//  //  }

//  //  impl File<()> {
//  //      pub fn root(secret: &Secret, servers: Vec<Name>) -> Result<File<()>, orange_name::Error> {
//  //          let files = secret.get_hardend(None, &[], "files")?;
//  //          Ok(File{
//  //              key: files.derive(&["key"]),
//  //              name: "".to_string(),
//  //              servers: servers.clone(),
//  //              payload: (),
//  //              datetime: DateTime::UNIX_EPOCH,
//  //              children: Some(Key::Secret(files.derive(&["children"])))
//  //          })
//  //      }
//  //  }

//  //  impl<T: Serialize + Hash> Hash for File<T> {
//  //      fn hash<H: Hasher>(&self, hasher: &mut H) {
//  //          self.key.hash(hasher);
//  //          self.servers.hash(hasher);
//  //          //Reserializing has no effect on already serialized files
//  //          Serialized(serde_json::to_string(&self.payload).unwrap()).hash(hasher);
//  //          self.datetime.hash(hasher);
//  //          self.children.hash(hasher);
//  //      }
//  //  }

//  //  impl<T: Serialize + for<'a> Deserialize<'a> + Hash + 'static> File<T> {
//  //      pub fn new(
//  //          secret: &Secret, mut path: PathBuf, index: usize, servers: Vec<Name>, payload: T, children: bool
//  //      ) -> Result<Self, Error> {
//  //          let files_key = secret.get_hardend(None, &path.to_ids(), "files")
//  //              .or(Err(Error::MissingPerms(path.clone())))?;
//  //          Ok(File{
//  //              key: files_key.derive(&["key"]).derive(&[index]),
//  //              name: path.last(),
//  //              servers,
//  //              payload,
//  //              datetime: now(),
//  //              children: children.then_some(Key::Secret(files_key.derive(&["children"])))
//  //          })
//  //      }

//  //      pub fn pointer(&self) -> Pointer {Pointer{
//  //          id: self.id(),
//  //          key: Key::Secret(self.key),
//  //          servers: self.servers.clone(),
//  //      }}

//  //      pub fn id(&self) -> Id {Id::hash(self)}

//  //      pub fn serialize_payload(self) -> Result<File<Serialized>, serde_json::Error> {
//  //          Ok(File{
//  //              key: self.key,
//  //              name: self.name,
//  //              servers: self.servers,
//  //              //Reserializing has no effect on already serialized files
//  //              payload: Serialized(serde_json::to_string(&self.payload)?),
//  //              datetime: self.datetime,
//  //              children: self.children
//  //          })
//  //      }
//  //  }

//  //  impl File<Serialized> {
//  //      pub fn deserialize_payload<T: Serialize + for<'a> Deserialize<'a>>(self) -> Result<File<T>, serde_json::Error> {
//  //          Ok(File{
//  //              key: self.key,
//  //              name: self.name,
//  //              servers: self.servers,
//  //              payload: serde_json::from_str(&self.payload.0)?,
//  //              datetime: self.datetime,
//  //              children: self.children
//  //          })
//  //      }
//  //  }

//  ///Attempt to create the file with the given payload
//  impl Command<PurserRequest> for Create {
//      type Output = Result<, PurserError>;

//      async fn run(self, mut ctx: Context) -> Self::Output {
//          let request = CreatePrivate(self.0);
//          let r = majority(ctx.run((request, self.1)).await);
//      }
//  }

//  ///Attempt to delete this file
//  ///As it traverses the channel it will read for new payloads
//  ///If a versioning extention is shown it will delete only if that version is also the latest version
//  pub struct Delete(PathBuf);
//  impl Command<PurserRequest> for Delete {
//      type Output = Result<, PurserError>;

//      async fn run(self, mut ctx: Context) -> Self::Output {
//          let request = CreatePrivate(self.0);
//          let r = majority(ctx.run((request, self.1)).await);
//      }
//  }

//  ///Reads the file if no versioning extention is provided it will read the latest version of the file
//  pub struct Read(PathBuf);
//  impl Command<PurserRequest> for Delete {
//      type Output = Result<, PurserError>;

//      async fn run(self, mut ctx: Context) -> Self::Output {
//          let request = CreatePrivate(self.0);
//          let r = majority(ctx.run((request, self.1)).await);
//      }
//  }

//  #[test]
//  fn test_caching() {
//      let mut cache = FileCache::default();
//  }
