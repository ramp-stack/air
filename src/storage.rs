use serde::{Serialize, Deserialize};
use easy_secp256k1::{EasySecretKey, EasyPublicKey, Signed as KeySigned};
use secp256k1::{SecretKey, PublicKey};

use std::hash::Hash;
use std::fmt::Debug;

use crate::orange_name::{OrangeResolver, OrangeSecret, OrangeName, Signed as DidSigned};
use crate::server::Error;
use crate::{DateTime, Id, now};

mod service;
pub use service::Service;

mod requests;
pub use requests::{Client, Processed};
pub mod records;

const NAME: &str = "STORAGE";

#[derive(Serialize, Deserialize, Clone, Debug, Hash, PartialEq, Eq)]
pub struct PrivateItem {
    pub discover: PublicKey,
    pub delete: Option<PublicKey>,
    pub payload: Vec<u8>
}

#[derive(Serialize, Deserialize, Clone, Debug, Hash)]
pub struct DMItem(OrangeName, Vec<u8>);

#[derive(Serialize, Deserialize, Clone, Debug, Hash)]
pub struct PublicItem {
    pub protocol: Id,
    pub header: Vec<u8>,
    pub payload: Vec<u8>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Hash)]
pub enum Op {LS, LSE, E, GRE, GR}

#[derive(Serialize, Deserialize, Clone, Debug, Hash)]
pub struct Filter{
    id: Option<Id>,
    author: Option<OrangeName>,
    protocol: Option<Id>,
    datetime: Option<(Op, DateTime)>
}
impl Filter {
    pub fn new(id: Option<Id>, author: Option<OrangeName>, protocol: Option<Id>, datetime: Option<(Op, DateTime)>) -> Self {
        Filter{id, author, protocol, datetime}
    }

    pub fn filter(&self, item: (Id, OrangeName, PublicItem, DateTime)) -> Option<(Id, OrangeName, PublicItem, DateTime)> {
        if let Some(id) = self.id {if item.0 != id {return None;}}
        if let Some(author) = &self.author {if item.1 != *author {return None;}}
        if let Some(protocol) = self.protocol {if item.2.protocol != protocol {return None;}}
        if let Some((op, datetime)) = &self.datetime {
            match op {
                Op::LS if item.3 >= *datetime => {return None;},
                Op::LSE if item.3 > *datetime => {return None;},
                Op::E if item.3 != *datetime => {return None;},
                Op::GRE if item.3 < *datetime => {return None;},
                Op::GR if item.3 <= *datetime => {return None;},
                _ => {}
            }
        }
        Some(item) 
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, Hash)]
pub struct Catalog {
    //cost_per_read: u32,
}

#[derive(Serialize, Deserialize, Clone, Debug, Hash)]
pub enum Request{
    CreatePrivate(KeySigned<PrivateItem>),//Discover Signed Item
    ReadPrivate(KeySigned<()>),//Signed Discover, Include Size Limit?
    UpdatePrivate(KeySigned<KeySigned<PrivateItem>>),//Discover Signed Delete Signed NewItem
    DeletePrivate(KeySigned<PublicKey>),//Delete Signed Discover

    CreatePublic(DidSigned<PublicItem>),
    ReadPublic(Filter),
    UpdatePublic(DidSigned<(Id, DidSigned<PublicItem>)>),
    DeletePublic(DidSigned<Id>),

    CreateDM(OrangeName, Vec<u8>),
    ReadDM(DidSigned<(DateTime, DateTime)>)
}

impl Request {
    pub fn create_private(sec_discover: &SecretKey, delete: Option<PublicKey>, payload: Vec<u8>) -> Self {
        let discover = sec_discover.easy_public_key();
        Request::CreatePrivate(KeySigned::new(PrivateItem{discover, delete, payload}, sec_discover))
    }
    pub fn read_private(discover: &SecretKey) -> Self {
        Request::ReadPrivate(KeySigned::new((), discover))
    }
    pub fn update_private(discover: &SecretKey, delete: &SecretKey, payload: Vec<u8>) -> Self {
        Request::UpdatePrivate(KeySigned::new(KeySigned::new(
            PrivateItem{discover: discover.easy_public_key(), delete: Some(delete.easy_public_key()), payload},
        discover), delete))
    }
    pub fn delete_private(discover: PublicKey, delete: &SecretKey) -> Self {
        Request::DeletePrivate(KeySigned::new(discover, delete))
    }

    pub async fn create_dm(resolver: &mut OrangeResolver, secret: &OrangeSecret, recipient: OrangeName, payload: Vec<u8>) -> Result<Self, Error> {
        let com = resolver.key(&recipient, Some("easy_access_com"), None).await?;
        Ok(Request::CreateDM(recipient, com.easy_encrypt(serde_json::to_vec(&(secret.name(), resolver.sign(secret, &payload).await?, payload)).unwrap()).unwrap()))
    }

    pub async fn read_dm(resolver: &mut OrangeResolver, secret: &OrangeSecret, since: DateTime) -> Result<Self, Error> {
        Ok(Request::ReadDM(DidSigned::new(resolver, secret, (now(), since)).await?))
    }

    pub async fn create_public(resolver: &mut OrangeResolver, secret: &OrangeSecret, item: PublicItem) -> Result<Self, Error> {
        Ok(Request::CreatePublic(DidSigned::new(resolver, secret, item).await?))
    }

    pub fn read_public(filter: Filter) -> Self {Request::ReadPublic(filter)}

    pub async fn update_public(resolver: &mut OrangeResolver, secret: &OrangeSecret, id: Id, item: PublicItem) -> Result<Self, Error> {
        let signed = DidSigned::new(resolver, secret, item).await?;
        Ok(Request::UpdatePublic(DidSigned::new(resolver, secret, (id, signed)).await?))
    }
    pub async fn delete_public(resolver: &mut OrangeResolver, secret: &OrangeSecret, id: Id) -> Result<Self, Error> {
        Ok(Request::DeletePublic(DidSigned::new(resolver, secret, id).await?))
    }
}

#[derive(Serialize, Deserialize, Default, Clone, Debug, Hash)]
pub enum Response {
    InvalidRequest(String),
    InvalidSignature(String),
    InvalidDelete(Option<PublicKey>),
    ReadPrivate(Option<(KeySigned<PrivateItem>, DateTime)>),
    PrivateConflict(KeySigned<PrivateItem>, DateTime),
    CreatedPublic(Id),
    ReadPublic(Vec<(Id, DidSigned<PublicItem>, DateTime)>),
    ReadDM(Vec<Vec<u8>>),
    #[default]
    Empty,
}
