use serde::{Serialize, Deserialize};
use easy_secp256k1::{EasySecretKey, Signed as KeySigned};
use secp256k1::{SecretKey, PublicKey};

use std::hash::Hash;
use std::fmt::Debug;

use crate::server::{Request as ChandlerRequest, Error, ServiceRequest};
use crate::{DateTime, Id};

use orange_name::{OrangeName, Signed as DidSigned};

//mod inner_records;

mod channels;

mod service;
pub use service::Service;

pub mod requests;
//pub use requests::{Client, Processed};

pub mod records;

//pub mod compiler;

const NAME: &str = "STORAGE";

#[derive(Serialize, Deserialize, Clone, Debug, Hash)]
pub struct PrivateItem {
    pub discover: PublicKey,
    pub delete: Option<PublicKey>,
    pub header: KeySigned<Vec<u8>>,
    pub payload: Vec<u8>
}

#[derive(Serialize, Deserialize, Clone, Debug, Hash)]
pub struct DMItem(OrangeName, Vec<u8>);

#[derive(Serialize, Deserialize, Clone, Debug, Hash, PartialEq, Eq)]
pub struct PublicItem {
    pub protocol: Id,
    pub header: Vec<u8>,
    pub payload: Vec<u8>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Hash, PartialEq, Eq)]
pub enum Op {LS, LSE, E, GRE, GR}

#[derive(Serialize, Deserialize, Clone, Debug, Hash, PartialEq, Eq)]
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

    pub fn filter(&self, oid: &Id, oauthor: &OrangeName, oitem: &PublicItem, odatetime: &DateTime) -> bool {
        if let Some(id) = &self.id && id != oid {return false;}
        if let Some(author) = &self.author && author != oauthor {return false;}
        if let Some(protocol) = &self.protocol && protocol != &oitem.protocol {return false;}
        if let Some((op, datetime)) = &self.datetime {
            match op {
                Op::LS if odatetime >= datetime => {return false;},
                Op::LSE if odatetime > datetime => {return false;},
                Op::E if odatetime != datetime => {return false;},
                Op::GRE if odatetime < datetime => {return false;},
                Op::GR if odatetime <= datetime => {return false;},
                _ => {}
            }
        }
        true
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
    ReadPrivateHeader(KeySigned<()>),
    DeletePrivate(KeySigned<PublicKey>),//Delete Signed Discover

    CreatePublic(DidSigned<PublicItem>),
    ReadPublic(Filter),
    UpdatePublic(DidSigned<(Id, DidSigned<PublicItem>)>),
    DeletePublic(DidSigned<Id>),

    CreateDM(OrangeName, Vec<u8>),
    ReadDM(DidSigned<(DateTime, DateTime)>)
}

impl ServiceRequest for Request {
    type Response = Response;
}

impl Request {
    pub fn create_private(sec_discover: &SecretKey, delete: Option<PublicKey>, header: Vec<u8>, payload: Vec<u8>) -> Self {
        let discover = sec_discover.easy_public_key();
        Request::CreatePrivate(KeySigned::new(PrivateItem{discover, delete, header: KeySigned::new(header, sec_discover), payload}, sec_discover))
    }
    pub fn read_private(discover: &SecretKey) -> Self {
        Request::ReadPrivate(KeySigned::new((), discover))
    }
    pub fn read_private_header(discover: &SecretKey) -> Self {
        Request::ReadPrivateHeader(KeySigned::new((), discover))
    }
    pub fn delete_private(discover: PublicKey, delete: &SecretKey) -> Self {
        Request::DeletePrivate(KeySigned::new(discover, delete))
    }

    pub fn create_dm(recipient: OrangeName, payload: Vec<u8>) -> Self {
        Request::CreateDM(recipient, payload)
    }
}

impl From<Request> for ChandlerRequest {
    fn from(req: Request) -> ChandlerRequest {
        ChandlerRequest::Service(NAME.to_string(), serde_json::to_string(&req).unwrap())
    }
}

pub type Item<I> = Option<(DateTime, Option<KeySigned<I>>)>;

#[allow(clippy::large_enum_variant)]
#[derive(Serialize, Deserialize, Default, Clone, Debug, Hash)]
pub enum Response {
    InvalidRequest(String),
    InvalidSignature(String),
    InvalidDelete(Option<PublicKey>),
    ReadPrivate(Item<PrivateItem>),
    ReadPrivateHeader(Item<Vec<u8>>),
    CreatePrivate(Option<DateTime>),
    CreatedPublic(Id),
    ReadPublic(Vec<(Id, DidSigned<PublicItem>, DateTime)>),
    ReadDM(Vec<Vec<u8>>),
    #[default]
    Empty,
}

impl Response {
    pub fn create_private(self) -> Result<Option<DateTime>, Error> {match self {
        Self::CreatePrivate(result) => Ok(result),
        r => Err(Error::mr(r))
    }}

    pub fn read_private_header(self) -> Result<Item<Vec<u8>>, Error> {match self {
        Self::ReadPrivateHeader(result) => Ok(result),
        r => Err(Error::mr(r))
    }}

    pub fn read_private(self) -> Result<Item<PrivateItem>, Error> {match self {
        Self::ReadPrivate(result) => Ok(result),
        r => Err(Error::mr(r))
    }}

    pub fn delete_private(self) -> Result<Option<Option<PublicKey>>, Error> {match self {
        Self::InvalidDelete(result) => Ok(Some(result)),
        Self::Empty => Ok(None),
        r => Err(Error::mr(r))
    }}

    pub fn create_dm(self) -> Result<(), Error> {match self {
        Self::Empty => Ok(()),
        r => Err(Error::mr(r))
    }}

    pub fn read_dm(self) -> Result<Vec<Vec<u8>>, Error> {match self {
        Self::ReadDM(result) => Ok(result),
        r => Err(Error::mr(r))
    }}

    pub fn create_public(self) -> Result<Id, Error> {match self {
        Self::CreatedPublic(result) => Ok(result),
        r => Err(Error::mr(r))
    }}

    pub fn read_public(self) -> Result<Vec<(Id, DidSigned<PublicItem>, DateTime)>, Error> {match self {
        Self::ReadPublic(result) => Ok(result),
        r => Err(Error::mr(r))
    }}

    pub fn update_public(self) -> Result<(), Error> {match self {
        Self::Empty => Ok(()),
        r => Err(Error::mr(r))
    }}

    pub fn delete_public(self) -> Result<(), Error> {match self {
        Self::Empty => Ok(()),
        r => Err(Error::mr(r))
    }}
}
