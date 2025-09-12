use super::inner_records::*;
use serde::{Serialize, Deserialize};
use orange_name::{OrangeResolver, OrangeName};
use std::collections::BTreeMap;
use std::hash::{Hasher, Hash};
use std::path::{Path, PathBuf};
use crate::Id;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Hash)]
pub enum Actor {
    Author(usize),//Owner
    Group(usize, String),
    User(OrangeName),
    Anyone(usize),//Dose this need to exist?

    And(Box<Actor>, Box<Actor>),
    //Or(Box<Actor>, Box<Actor>),Or is built in when you list two different actors to the same
    //action
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Hash)]
pub enum Action {//CreateChild implies ReadChild, Update Impls Read
    Create,
    Update, //Updating a Record includes giving or removing permissions and or updating payload???
    Delete,
    Read, //Discover and Read Self
  //CreateChild(PathBuf), //Empty to allow any child, Create a child with the given name (path and regex accepted) Needs Discover and Read children
  //ReadChild(PathBuf), //Read a child with the given name (path and regex accepted)
  //UpdateChild(PathBuf), //Update a child with the given name (path and regex accepted)
  //DeleteChild(PathBuf), //Delete a child with the given name (path and regex accepted)
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Hash)]
pub struct Permission(Actor, Action);

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Hash)]
pub enum Children {
    Map(Vec<OrangeName>, Id),
    Struct(BTreeMap<String, (Vec<OrangeName>, Id)>),
    None
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Protocol(PathBuf, Id, String, Children, Vec<Permission>, BTreeMap<String, Vec<OrangeName>>);
impl Protocol {
    pub fn id(&self) -> Id {self.1}
    pub fn new(name: &str, children: Children, permissions: Vec<Permission>, groups: BTreeMap<String, Vec<OrangeName>>) -> Self {
        let name = name.to_string();
        let id = Id::hash(&(&name, &children, &permissions));
        Protocol(PathBuf::from(id.to_string()), id, name, children, permissions, groups)
    }

    pub fn permissions(&self, path: &[String]) -> Vec<Permission> {
        
    }
}
impl Hash for Protocol {fn hash<H: Hasher>(&self, state: &mut H) {self.1.hash(state)}}
impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {write!(f, "{}", self.1)}
}
impl AsRef<Path> for Protocol {fn as_ref(&self) -> &Path {&self.0}}

#[derive(Serialize, Deserialize, PartialEq, Eq, Clone, Debug, Hash)]
pub struct Header{
    name: String,
    protocol: Id,
    first_payload: Id,
    key_set: Keys 
}

impl Header {
    //Verifing with a different parent can change the validity of the header
    fn verify(&self, resolver: &mut OrangeResolver, cache: &Cache, path: &[String]) {
    }
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Clone, Debug)]
pub struct Keys {
    discover: SecretKey,
    anyone: SecretKey,
    read: SecretKey,
    others: BTreeMap<Id, Key>,
}
impl Hash for Keys {fn hash<H: Hasher>(&self, state: &mut H) {
    state.write(&self.discover.secret_bytes()); state.write(&self.read.secret_bytes()); self.others.hash(state);
}}
impl KeySet {
    //fn get_perm_key(&self, permission: &Permission) ->
}

mod test {
    use super::*;
    #[test]
    fn test() {
        let endpoints = vec![];

        let comment = Protocol::new("Comment", Children::None, vec![
            Permission(Actor::Anyone(1), Action::Create),//Anyone who can read message can create
            Permission(Actor::Author(0), Action::Delete),//Author can delete
            Permission(Actor::Author(1), Action::Delete),//Author of message can delete
            Permission(Actor::Group(3, "Admin"), Action::Delete),//Group admin of room can delete
        ], BTreeMap::default());

        let message = Protocol::new("Message", Children::Map(endpoints.clone(), comment.id()), vec![
            Permission(Actor::Author(2), Action::Delete),//Author of room can delete
            Permission(Actor::Author(0), Action::Delete),//Author can delete
            Permission(Actor::Author(1), Action::Create),//Author of messages can create
            Permission(Actor::Anyone(1), Action::Create),//Anyone who can read messages can create 
            Permission(Actor::Anyone(1), Action::Read),//Anyone who can read messages can read
            Permission(Actor::And(Box::new(Actor::Author(2)), Box::new(Actor::Author(0))), Action::Update)
                                //Author of room and Author of message can update
            Permission(Actor::Group(2, "Admin"), Action::Delete),//Group admin of room can delete
        ], BTreeMap::default());

        let messages = Protocol::new("Messages", Children::Map(endpoints.clone(), message.id()), vec![
            Permission(Actor::Author(1), Action::Create),//Author of room can create
            Permission(Actor::Anyone(1), Action::Read),//Anyone who can read room can read
        ], BTreeMap::default());

        let name = Protocol::new("Name", Children::None, vec![
            Permission(Actor::Author(2), Action::Create),//Author of room can create
            Permission(Actor::Author(0), Action::Delete),//Author can delete
            Permission(Actor::Anyone(1), Action::Read),//Anyone who can read names can read
        ], BTreeMap::default());

        let names = Protocol::new("Names", Children::Map(endpoints.clone(), name.id()), vec![
            Permission(Actor::Author(1), Action::Create),//Author of room can create
            Permission(Actor::Anyone(1), Action::Read),//Anyone who can read room can read
        ], BTreeMap::default());

        let room = Protocol::new("Room", Children::Struct(BTreeMap::from([
                ("names".to_string(), (endpoints.clone(), names.id())),
                ("messages".to_string(), (endpoints.clone(), messages.id()))
        ])), vec![
            Permission(Actor::Anyone(0), Action::Create),
            Permission(Actor::Author(0), Action::Read),
        ], BTreemap::from(["admin".to_string(), vec![bob, alice, charlie]]));

        panic!("{:#?}", room);
    }
}


