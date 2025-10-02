use serde::{Serialize, Deserialize};

use std::hash::Hash;
use std::fmt::Debug;

use crate::server::{ServiceRequest, Error, RawRequest, map_request_enum};
use crate::{DateTime};

use orange_name::{secp256k1::{PublicKey, Signed as KeySigned}, Id};

mod files;
pub use files::{PrivateItem, DirectedItem, PublicItem, Op, Filter, File, FileCache, CreateFile, DiscoverFile, ReadFile};

mod service;
pub use service::Service;

#[derive(Serialize, Deserialize, Clone, Debug, Hash)]
pub struct Catalog {
    //cost_per_read: u32,
}

#[derive(Serialize, Deserialize, Clone, Debug, Hash)]
pub enum Request{
    CreatePrivate(KeySigned<PrivateItem>),
    ReadPrivate(KeySigned<()>),
    ReadPrivateHash(KeySigned<()>),

  //CreatePublic(OrangeSigned<PublicItem>),
  //UpdatePublic(OrangeSigned<(Id, OrangeSigned<PublicItem>)>),
  //DeletePublic(OrangeSigned<Id>),

  //CreateDirected(Name, Vec<u8>),
  //ReadDirected(OrangeSigned<(DateTime, DateTime)>)
}
impl ServiceRequest for Request {type Response = Response; type Service = Service;}

#[derive(Serialize, Deserialize, Clone, Debug, Hash)]
pub enum Response {
    CreatePrivate(Option<DateTime>),
    ReadPrivate(Option<(DateTime, Id, KeySigned<PrivateItem>)>),
    ReadPrivateHash(Option<(DateTime, Id)>),


    InvalidRequest(String),
    InvalidSignature(String),
    InvalidDelete(Option<PublicKey>),

  //CreatedPublic(Id),
  //ReadPublic(Vec<(Id, OrangeSigned<PublicItem>, DateTime)>),
  //ReadDirected(Vec<Vec<u8>>),
  //Empty,
}

//TODO: Create a proc_macro ServiceRequest(Service, Response) that auto generates everything except the enums
map_request_enum!(Request::CreatePrivate: KeySigned<PrivateItem> => Response: Option<DateTime>);
//TODO: Need to validate that the Id matches a hash of the KeySigned<PrivateItem>
map_request_enum!(Request::ReadPrivate: KeySigned<()> => Response: Option<(DateTime, Id, KeySigned<PrivateItem>)>);
map_request_enum!(Request::ReadPrivateHash: KeySigned<()> => Response: Option<(DateTime, Id)>);
