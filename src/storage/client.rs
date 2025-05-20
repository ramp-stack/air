use super::{Error, NAME};
use secp256k1::{SecretKey, PublicKey};
use crate::service::Request;

pub struct Client {}

impl Client {
    pub fn new() -> Self {
        Client{}
    }

    pub async fn create_private(discover: SecretKey, delete: Option<PublicKey>, payload: Vec<u8>) -> Result<Request, Error> {
        Ok(Request::Service(NAME.to_string(), serde_json::to_string(Signed::new(PrivateItem{discover: discover.easy_public_key(), delete, payload})?)?))
    }
}
