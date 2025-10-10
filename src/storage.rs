use serde::{Serialize, Deserialize};

use std::hash::Hash;
use std::fmt::Debug;

use crate::server::{ServiceRequest, Error, RawRequest, map_request_enum};
use crate::{DateTime};

use orange_name::{secp256k1::{PublicKey, Signed as KeySigned}, Id};

mod private_item;
pub use private_item::{PrivateItem, Create as CreatePrivateItem, Read as ReadPrivateItem, CreateRead as CreateReadPrivateItem};

mod channels;
pub use channels::{Channel};

//  mod files;
//  pub use files::{File, FileCache, Key};

//pub mod records;

mod service;
pub use service::Service;

#[derive(Serialize, Deserialize, Clone, Debug, Hash)]
pub struct Catalog {
    //cost_per_read: u32,
}

#[derive(Serialize, Deserialize, Clone, Debug, Hash)]
pub enum Request{
    CreatePrivate(KeySigned<PrivateItem>),
    CreateReadPrivate(KeySigned<PrivateItem>),
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
    CreatePrivate(Option<(DateTime, Id)>),
    CreateReadPrivate(Option<(Id, KeySigned<PrivateItem>)>),
    ReadPrivate(Option<(Id, KeySigned<PrivateItem>)>),
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
map_request_enum!(Request::CreatePrivate: KeySigned<PrivateItem> => Response: Option<(DateTime, Id)>);
map_request_enum!(Request::CreateReadPrivate: KeySigned<PrivateItem> => Response: Option<(Id, KeySigned<PrivateItem>)>);
//TODO: Need to validate that the Id matches a hash of the KeySigned<PrivateItem>
map_request_enum!(Request::ReadPrivate: KeySigned<()> => Response: Option<(Id, KeySigned<PrivateItem>)>);
map_request_enum!(Request::ReadPrivateHash: KeySigned<()> => Response: Option<(DateTime, Id)>);


//  #[derive(Serialize, Deserialize, Clone, Debug, Hash)]
//  pub struct DirectedItem(PublicKey, Vec<u8>);

//  impl DirectedItem {
//      pub fn new(secret: &Secret, recipient: PublicKey, payload: Vec<u8>) -> Result<Self, orange_name::Error>{
//          let signed = OrangeSigned::new(secret, &[], payload)?;
//          Ok(DirectedItem(recipient, recipient.encrypt(serde_json::to_vec(&signed).unwrap()).unwrap()))
//      }

//      pub async fn verify(self, resolver: &mut Resolver, secret: &SecretKey) -> Result<(Name, Vec<u8>), orange_name::Error> {
//          let signed = serde_json::from_slice::<OrangeSigned<Vec<u8>>>(&secret.decrypt(&self.1)?)
//              .map_err(|_| secp256k1::Error::InvalidMessage)?;
//          Ok((signed.signer(), signed.verify(resolver, None, None, None).await?))
//      }
//  }

//  #[derive(Serialize, Deserialize, Clone, Debug, Hash, PartialEq, Eq)]
//  pub struct PublicItem {
//      pub tags: BTreeSet<String>,
//      pub payload: Vec<u8>,
//  }

//  #[derive(Serialize, Deserialize, Clone, Debug, Hash, PartialEq, Eq)]
//  pub enum Op {LS, LE, E, GE, GR}

//  #[derive(Serialize, Deserialize, Clone, Debug, Hash, PartialEq, Eq)]
//  pub struct Filter{
//      pub id: Option<Id>,
//      pub author: Option<Name>,
//      pub tags: Option<BTreeSet<String>>,
//      pub datetime: Option<(Op, DateTime)>
//  }
//  impl Filter {
//      pub fn new(
//          id: Option<Id>, author: Option<Name>, tags: Option<BTreeSet<String>>, datetime: Option<(Op, DateTime)>
//      ) -> Self {
//          Filter{id, author, tags, datetime}
//      }

//      pub fn filter(&self, oid: &Id, oauthor: &Name, oitem: &PublicItem, odatetime: &DateTime) -> bool {
//          if let Some(id) = &self.id && id != oid {return false;}
//          if let Some(author) = &self.author && author != oauthor {return false;}
//          if let Some(tags) = &self.tags && !tags.is_subset(&oitem.tags) {return false;}
//          if let Some((op, datetime)) = &self.datetime {
//              match op {
//                  Op::LS if odatetime >= datetime => {return false;},
//                  Op::LE if odatetime > datetime => {return false;},
//                  Op::E if odatetime != datetime => {return false;},
//                  Op::GE if odatetime < datetime => {return false;},
//                  Op::GR if odatetime <= datetime => {return false;},
//                  _ => {}
//              }
//          }
//          true
//      }
//  }


