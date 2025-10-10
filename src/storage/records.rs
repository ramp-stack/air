use std::path::{PathBuf, Path};
use serde::{Serialize, Deserialize};
use orange_name::{Name, Id, Signed, Resolver, Secret};
use std::collections::BTreeMap;
use std::hash::{Hasher, Hash};
use crate::server::{PurserRequest as Request, Context, Command, Error as PurserError};

use super::files::{Error as FileError, File, RequestError, DiscoverFile, Pointer};

mod consensus;

#[derive(Debug)]
pub enum Error {
    MissingPerms(PathBuf),
    MissingRecord(PathBuf),
    InvalidPath(PathBuf),
    FileError(FileError),
    PurserError(PurserError),
}
impl std::error::Error for Error {}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {write!(f, "{self:?}")}
}
impl From<PurserError> for Error {fn from(e: PurserError) -> Error {Error::PurserError(e)}}
impl From<FileError> for Error {fn from(e: FileError) -> Error {Error::FileError(e)}}
impl From<RequestError> for Error {fn from(e: RequestError) -> Error {match e {
    RequestError::FileError(e) => Error::FileError(e),
    RequestError::PurserError(e) => Error::PurserError(e),
}}}


//Records have a path system, more than an id system since a record can exist in two different
//paths and will be expected to be interacted with a different signature based on the path from
//root

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

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Hash)]
pub struct Record {//Header
    name: String,
    author: Name,
    protocol: Protocol,
    payload_file: Option<Pointer, Option<Vec<(Name, Vec<u8>)>>>,
    //If this record has a payload here is the pointer, If the pointer is public because reads are
    //restricted to not anyone then an optional list of encrypted keys for the payload which should
    //match the pointers public key are provided, No guarentees that the encrypted payloads are not
    //garbage assuming they are all 64+64 in length (+16 for auth tag?)
}

impl Record {
    pub fn root(author: Name, servers: Vec<Name>) -> Self {
        Record{
            name: String::new(),
            author,
            protocol: Protocol::root(servers),
            payload_file: None
        }
    }

  //pub fn protocol_folder(author: Name, servers: Vec<Name>, protocol_id: Id) -> Self {
  //    Record{
  //        name: protocol_id.to_string(),
  //        author,
  //        protocol: Protocol::protocol_folder(servers, protocol_id),
  //        payload_file: None
  //    }
  //}
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct RecordTree {
    file: Id,
    record: Record,
    children: (usize, BTreeMap<String, RecordTree>),//(latest_index, children)
}

impl RecordTree {
    pub fn get<P: AsRef<Path>>(&self, path: P) -> Option<&RecordTree> {
        if path.as_ref() == PathBuf::new() {Some(self)} else {
            self.children.1.get(
                path.as_ref().components().next().unwrap().as_os_str().to_string_lossy().as_ref()
            ).and_then(|node| node.get(path))
        }
    }

    pub fn get_mut<P: AsRef<Path>>(&mut self, path: P) -> Option<&mut RecordTree> {
        if path.as_ref() == PathBuf::new() {Some(self)} else {
            self.children.1.get_mut(
                path.as_ref().components().next().unwrap().as_os_str().to_string_lossy().as_ref()
            ).and_then(|node| node.get_mut(path))
        }
    }
}

#[derive(Serialize, Deserialize, Default, Clone, Debug)]
pub struct RecordCache(Option<(PathBuf, RecordTree)>);//last item in pathBuf matches Record Tree Record Name
impl RecordCache {
    pub fn is_empty(&self) -> bool {self.0.is_none()}
    pub fn new(path: PathBuf, file: Id, record: Record) -> Self {
        RecordCache(Some((path, RecordTree{file, record, children: (0, BTreeMap::new())}))) 
    }
    pub fn get<P: AsRef<Path>>(&self, path: P) -> Option<&RecordTree> {
        self.0.as_ref().and_then(|(prefix, node)|
            path.as_ref().strip_prefix(prefix).ok().and_then(|path| node.get(path))
        )
    }

    pub fn get_mut<P: AsRef<Path>>(&mut self, path: P) -> Option<&mut RecordTree> {
        self.0.as_mut().and_then(|(prefix, node)|
            path.as_ref().strip_prefix(prefix).ok().and_then(|path| node.get_mut(path))
        )
    }
}

//In order to know the current status of any record we need to read the current state of the parent
//channel

///For Discovering/Reading the current state of all this records children
pub struct DiscoverRecordChildren(PathBuf);
impl Command<Request> for DiscoverRecordChildren {
    type Output = Result<(), Error>;
    async fn run(self, mut ctx: Context) -> Self::Output {
        let mut state = ctx.store().await;
        let cache = state.get::<RecordCache>().unwrap();
        let parent = cache.get(&self.0).ok_or(Error::MissingRecord(self.0.clone()))?;
        let parent_file = parent.file;
        let mut latest_index = parent.children.0;
        drop(state);
        while let Some(file) = ctx.run(DiscoverFile(parent_file, latest_index)).await? {
            if let Some(file) = file.and_then(|file| file.deserialize_payload::<Signed<FileAction>>().ok()) {
                let mut state = ctx.store().await;
                let resolver = state.get_mut_or_default::<Resolver>();
                let signer = file.payload.signer();
                if let Ok(file) = file.payload.verify(
                    resolver, None, Some(&file.timestamp), Some(&consensus::path_to_ids(&self.0))
                ).await {
                    panic!("valid record file found: {:?}", file);
                }
              //let mut cache = store.get_mut::<RecordCache>().unwrap();
              //let mut parent = cache.get_mut(&self.0).unwrap();
              //parent.children.1.get(

            }
            latest_index += 1;
        }
        let mut cache = ctx.get_mut::<RecordCache>().await.unwrap();
        let mut parent = cache.get_mut(&self.0).unwrap();
        parent.children.0 = latest_index;
        
        //Start from the child index and read new files untill end
        //
        //Process files validate and update RecordTree Info
        Ok(())
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Hash)]
enum FileAction {
    Create(Record),
    Update(Record, bool),//Name, Payload, Keep Children
    Delete(String)
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Hash)]
pub enum RecordAction {
    Create(PathBuf, Protocol, Option<Vec<u8>>),
    Update(PathBuf, Protocol, Option<Vec<u8>>, bool),
    Delete(PathBuf)
}

///For Create/Update/Delete Child Actions on the Parent

pub struct CreateChild(pub RecordAction);
impl Command<Request> for CreateChild {
    type Output = Result<(), Error>;
    async fn run(self, mut ctx: Context) -> Self::Output {
        match self.0 {
            RecordAction::Create(mut path, protocol, payload) => {
                let mut state = ctx.store().await;
                let secret = state.get::<Secret>().unwrap();
                let record_name = path.file_name()
                    .ok_or(Error::InvalidPath(path.clone()))?
                    .to_string_lossy().to_string();
                let ids = consensus::path_to_ids(path);
                path.pop();
                let parent_path = path;
                let mut cache = state.get_mut::<RecordCache>().unwrap();
                let mut parent = cache.get_mut(&parent_path)
                    .ok_or(Error::MissingRecord(parent_path.clone()))?;
                let channel = secret.get_hardend(None, &ids)?.derive(&["records", "payload"]);
              //if let Some(payload) = payload {
              //    let file = File{
              //        //derived from secret in a predictable way /path/hardend/records/payload
              //        key: secret.derive(path),
              //    }
              //}
              //let record = Record{
              //    name: record_name,
              //    author: secret.name(),
              //    protocol,
              //    payload: Some(pointer)
              //};
                todo!()

            },
            _ => todo!()
        }
    }
}



///For reading the optional payload of a record
pub struct ReadRecord(PathBuf);
