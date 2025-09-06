use serde::{Serialize, Deserialize};
use easy_secp256k1::{EasySecretKey, EasyPublicKey, Signed as KeySigned};
use secp256k1::{SecretKey, PublicKey};

use std::hash::Hash;
use std::fmt::Debug;

use crate::orange_name::{OrangeResolver, OrangeSecret, OrangeName, Signed as DidSigned};
use crate::server::{Request as ChandlerRequest, Error, ServiceRequest};
use crate::{DateTime, Id, now};

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
