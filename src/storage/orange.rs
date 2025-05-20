use easy_secp256k1::{EasySecretKey, EasyPublicKey, EasyHash, Hashable, Signed as KeySigned};
use secp256k1::{SecretKey, PublicKey};
use serde::{Serialize, Deserialize};
use crate::did::{DidResolver, DidSecret};
use super::{records};
use records::{ValidationError, Id};

//  ///Rooms are signed by the author
//  pub struct CreateRoom(DidSignature);
//  ///Rooms are assigned a read key by the author
//  pub struct ReadRoom(Key);
//  ///Rooms are assigned a read key by the author
//  pub struct DeleteRoom(Key);

//  ///Messages are signed by the author
//  pub struct CreateMessage(DidSignature);
//  ///Messages use the room read key
//  pub struct ReadMessage(Key);
//  ///Messages use the room delete key
//  pub struct DeleteMessage(Key);

//  ///Comments are signed by the author of the message
//  pub struct CreateTag(DidSignature);
//  ///Comments use the room read key | author decided Key
//  pub struct ReadTag(Key, Key);
//  ///Messages use the room delete key | author decided key
//  pub struct DeleteTag(Key, Key);

//  ///Comments are signed by the author
//  pub struct CreateComment(DidSignature);
//  ///Comments use the room read key
//  pub struct ReadComent(Key);
//  ///Messages use the room delete key | author decided key
//  pub struct DeleteComment(Key, Key);
//

#[derive(serde_with::SerializeDisplay)]
#[derive(serde_with::DeserializeFromStr)]
pub struct DidCreate(Box<dyn DidResolver>, Box<dyn DidSecret>);
#[typetag::serde]
#[async_trait::async_trait(?Send)]
impl records::Create for DidCreate {
    fn id(&self) -> Id {Id::from([10; 32])}

    async fn sign(&mut self, payload: &[u8]) -> Result<Vec<u8>, ValidationError> {
        Ok(self.0.sign(self.1.clone(), payload).await.map(|sig| serde_json::to_vec(&sig).unwrap())?)
    }
}
impl std::fmt::Display for DidCreate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        todo!()
        //write!(f, "did:{}:{}", self.0, self.1)
    }
}
impl std::str::FromStr for DidCreate {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        todo!()
    }
}

pub struct Client {
    did_resolver: Box<dyn DidResolver>,
    cache: &mut Cache
}

pub struct Room {
    name: DidSigned<String>,
}

impl Room {
    pub fn new(name: String) -> Self {

    }

    pub fn validate(&self) -> Result<(), ValidationError> {

    }

    pub fn send_message(&self, message: Message) -> Id {

    }

    pub fn get_message(&self, id: Id) -> Option<Message> {

    }

    pub fn discover(&self, start: usize, gap: usize) -> Vec<Message> {

    }
}

//  pub struct Message {
//      message: DidSigned<String>,
//  }
//  impl Message {
//      pub fn validate(&self) {

//      }
//  }




pub struct RoomProtocol;
impl Protocol for RoomProtocol {
    fn child_set(cache: &mut Cache, parent_id: &Id, index: u32) -> Result<KeySet, ValidationError> {
        let parent = cache.get(parent_id).ok_or(ValidationError::MissingRecord(*parent_id))?;
        let children = parent.children.as_ref().and_then(|c| c.secret()).ok_or(ValidationError::InvalidParent(*parent_id))?;
        let child = children.easy_derive(&[(u8::MAX as u32 * 2) + index])?;
        Ok(KeySet {
            discover: child.easy_derive(&[0])?,
            delete: None,
            read: Key::Secret(child.easy_derive(&[1])?),
            children: None,
            other: BTreeMap::new()
        })
    }
}
