use super::inner_records::*;
use serde::{Serialize, Deserialize};
use orange_name::{OrangeResolver, OrangeName};
use std::collections::BTreeMap;
use std::hash::{Hasher, Hash};
use std::path::{Path, PathBuf};
use crate::Id;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Hash)]
///"Or", or "Any" is provided by default when listing two permissions with different actors but the same action
pub enum Actor {
    ///Author of a parent record, 0 indicates self
    Author(usize),
    ///Anyone who can read a parent record, 0 indicates self
    Anyone(usize),
    ///Anyone who belongs to a group defined in a parent record, 0 indicates self
    Group(usize, String),
    User(OrangeName),
    ///Requires all actors to work together in other to take action
    All(Vec<Box<Actor>>),
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Hash)]
pub enum Action {
    ///Allows for creation of this record
    Create,
    ///Allows for updating the Payload and Protocol/Permissions (To limit the allowed protocols list them in the parent).
    Update,
    ///Allows for deleting the records payload, (Children are unaffected)
    Delete,
    ///Warning: Read actions are not enforeced, we have not yet implemented the ability to verify
    ///someone actually can read or that what they are reading is what they expected
    Read,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Hash)]
pub struct Permission(Actor, Action);

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Hash)]
pub struct Children(Vec<OrangeName>, Vec<Id>);

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Protocol(PathBuf, Id, String, Children, Vec<Permission>, BTreeMap<String, Vec<OrangeName>>);
impl Protocol {
    pub fn id(&self) -> Id {self.1}
    pub fn new(name: &str, children: Children, permissions: Vec<Permission>, groups: BTreeMap<String, Vec<OrangeName>>) -> Self {
        let name = name.to_string();
        let id = Id::hash(&(&name, &children, &permissions));
        Protocol(PathBuf::from(id.to_string()), id, name, children, permissions, groups)
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



mod test {
    use super::*;
    #[test]
    fn test() {
        let endpoints = vec![];

        let comment = Protocol::new("Comment", None, vec![
            Permission(Actor::Anyone(1), Action::Create),//Anyone who can read message can create
            Permission(Actor::Author(0), Action::Delete),//Author can delete
            Permission(Actor::Author(1), Action::Delete),//Author of message can delete
            Permission(Actor::Group(3, "Admin"), Action::Delete),//Group admin of room can delete
        ], BTreeMap::default());

        let message = Protocol::new("Message", Some(Children(endpoints.clone(), vec![comment.id()])), vec![
            Permission(Actor::Author(2), Action::Delete),//Author of room can delete
            Permission(Actor::Author(0), Action::Delete),//Author can delete
            Permission(Actor::Author(1), Action::Create),//Author of messages can create
            Permission(Actor::Anyone(1), Action::Create),//Anyone who can read messages can create 
            Permission(Actor::Anyone(1), Action::Read),//Anyone who can read messages can read
            Permission(Actor::And(Box::new(Actor::Author(2)), Box::new(Actor::Author(0))), Action::Update)
                                //Author of room and Author of message can update
            Permission(Actor::Group(2, "Admin"), Action::Delete),//Group admin of room can delete
        ], BTreeMap::default());

        let messages = Protocol::new("Messages", Some(Children(endpoints.clone(), vec![message.id()])), vec![
            Permission(Actor::Author(1), Action::Create),//Author of room can create
            Permission(Actor::Anyone(1), Action::Read),//Anyone who can read room can read
        ], BTreeMap::default());

        let name = Protocol::new("Name", None, vec![
            Permission(Actor::Author(2), Action::Create),//Author of room can create
            Permission(Actor::Author(0), Action::Delete),//Author can delete
            Permission(Actor::Anyone(1), Action::Read),//Anyone who can read names can read
        ], BTreeMap::default());

        let names = Protocol::new("Names", Some(Children(endpoints.clone(), vec![name.id()])), vec![
            Permission(Actor::Author(1), Action::Create),//Author of room can create
            Permission(Actor::Anyone(1), Action::Read),//Anyone who can read room can read
        ], BTreeMap::default());

        let room = Protocol::new("Room", Some(Children(endpoints.clone(), vec![names.id(), messages.id()])), vec![
            Permission(Actor::Anyone(0), Action::Create),
            Permission(Actor::Author(0), Action::Read),
        ], BTreemap::from(["admin".to_string(), vec![bob, alice, charlie]]));

        panic!("{:#?}", room);
    }
}


