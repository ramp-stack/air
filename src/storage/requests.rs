use secp256k1::{SecretKey, PublicKey};
use easy_secp256k1::{EasySecretKey, EasyPublicKey, Signed as KeySigned};
use serde::{Serialize, Deserialize};

use super::service::{Request, Response};
use super::{PrivateItem, NAME, ReadDMResult};
use crate::server::{Request as RequestTrait, ServiceRequest, ChandlerRequest, ChandlerResponse, Error};
use chrono::Utc;

use crate::did::{self, DidResolver, DidSecret, Signature, Did};

fn mr(response: Response) -> Error {Error::MaliciousResponse(format!("{:?}", response))}

#[derive(Serialize, Deserialize, Clone, Debug, Hash)]
pub struct InnerRequest(ServiceRequest);
impl AsRef<ChandlerRequest> for InnerRequest {fn as_ref(&self) -> &ChandlerRequest {self.0.as_ref()}}
impl From<Request> for InnerRequest {
    fn from(request: Request) -> Self {InnerRequest(ServiceRequest::new(NAME, &request).unwrap())}
}
impl RequestTrait for InnerRequest {
    type Output = Result<Response, Error>;
    fn process(self, response: Result<ChandlerResponse, Error>) -> Self::Output {
        serde_json::from_str(&self.0.process(response)?).map_err(|e| Error::MaliciousResponse(e.to_string()))
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, Hash)]
pub struct CreatePrivate(InnerRequest, PublicKey);
impl AsRef<ChandlerRequest> for CreatePrivate {fn as_ref(&self) -> &ChandlerRequest {self.0.as_ref()}}
impl CreatePrivate {
    pub fn new(sec_discover: &SecretKey, delete: Option<PublicKey>, payload: Vec<u8>) -> Self {
        let discover = sec_discover.easy_public_key();
        CreatePrivate(Request::CreatePrivate(KeySigned::new(PrivateItem{discover, delete, payload}, sec_discover)).into(), discover)
    }
}
impl RequestTrait for CreatePrivate {
    type Output = Result<Option<PrivateItem>, Error>;

    fn process(self, response: Result<ChandlerResponse, Error>) -> Self::Output {
        match self.0.process(response)? {
            Response::PrivateConflict(signed) if *signed.signer() == self.1 && signed.verify().is_ok() => Ok(Some(signed.into_inner())),
            Response::Empty => Ok(None),
            res => Err(mr(res))
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, Hash)]
pub struct ReadPrivate(InnerRequest, PublicKey);
impl AsRef<ChandlerRequest> for ReadPrivate {fn as_ref(&self) -> &ChandlerRequest {self.0.as_ref()}}
impl ReadPrivate {
    pub fn new(discover: &SecretKey) -> Self {
        ReadPrivate(Request::ReadPrivate(KeySigned::new((), discover)).into(), discover.easy_public_key())
    }
}
impl RequestTrait for ReadPrivate {
    type Output = Result<Option<PrivateItem>, Error>;

    fn process(self, response: Result<ChandlerResponse, Error>) -> Self::Output {
        match self.0.process(response)? {//If the signed item does not match discover key then the air server is to blame but if the item itself contains
            Response::ReadPrivate(Some(signed)) if
                *signed.signer() == self.1 &&
                signed.verify().is_ok() &&
                signed.as_ref().discover == self.1 
                => Ok(Some(signed.into_inner())),
            Response::ReadPrivate(None) => Ok(None),
            res => Err(mr(res))
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, Hash)]
pub struct UpdatePrivate(InnerRequest, pub(crate) PublicKey);
impl AsRef<ChandlerRequest> for UpdatePrivate {fn as_ref(&self) -> &ChandlerRequest {self.0.as_ref()}}
impl UpdatePrivate {
    pub fn new(discover: &SecretKey, sec_delete: &SecretKey, payload: Vec<u8>) -> Self {
        let delete = sec_delete.easy_public_key();
        UpdatePrivate(Request::UpdatePrivate(KeySigned::new(KeySigned::new(
            PrivateItem{discover: discover.easy_public_key(), delete: Some(delete), payload},
        discover), sec_delete)).into(), delete)
    }
}
impl RequestTrait for UpdatePrivate {
    type Output = Result<Option<Option<PublicKey>>, Error>;

    fn process(self, response: Result<ChandlerResponse, Error>) -> Self::Output {
        match self.0.process(response)? {
            Response::Empty => Ok(None),
            Response::InvalidDelete(key) if key == Some(self.1) => Err(Error::MaliciousResponse(
                "Claimed given key was the valid delete key in an InvalidDelete Response".to_string()
            )),
            Response::InvalidDelete(key) => Ok(Some(key)),
            res => Err(mr(res))
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, Hash)]
pub struct DeletePrivate(InnerRequest, pub(crate) PublicKey);
impl AsRef<ChandlerRequest> for DeletePrivate {fn as_ref(&self) -> &ChandlerRequest {self.0.as_ref()}}
impl DeletePrivate {
    pub fn new(discover: PublicKey, delete: &SecretKey) -> Self {
        DeletePrivate(Request::DeletePrivate(KeySigned::new(discover, delete)).into(), delete.easy_public_key())
    }
}
impl RequestTrait for DeletePrivate {
    type Output = Result<Option<Option<PublicKey>>, Error>;

    fn process(self, response: Result<ChandlerResponse, Error>) -> Self::Output {
        match self.0.process(response)? {
            Response::Empty => Ok(None),
            Response::InvalidDelete(key) if key == Some(self.1) => Err(Error::MaliciousResponse(
                "Claimed given key was the valid delete key in an InvalidDelete Response".to_string()
            )),
            Response::InvalidDelete(key) => Ok(Some(key)),
            res => Err(mr(res))
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, Hash)]
pub struct CreateDM(InnerRequest);
impl AsRef<ChandlerRequest> for CreateDM {fn as_ref(&self) -> &ChandlerRequest {self.0.as_ref()}}
impl CreateDM {
    pub async fn new(resolver: &mut dyn DidResolver, secret: impl DidSecret, recipient: Did, payload: Vec<u8>) -> Result<Self, did::Error> {
        let com = resolver.key(&recipient, Some("easy_access_com"), None).await?;
        Ok(CreateDM(Request::CreateDM(recipient, com.easy_encrypt(serde_json::to_vec(&(secret.did(), resolver.sign(Box::new(secret), &payload).await?, payload)).unwrap()).unwrap()).into()))
    }
}
impl RequestTrait for CreateDM {
    type Output = Result<(), Error>;

    fn process(self, response: Result<ChandlerResponse, Error>) -> Self::Output {
        match self.0.process(response)? {
            Response::Empty => Ok(()),
            res => Err(mr(res))
        }
    }
}

#[derive(Clone)]
pub struct ReadDM(InnerRequest, Box<dyn DidSecret>);
impl AsRef<ChandlerRequest> for ReadDM {fn as_ref(&self) -> &ChandlerRequest {self.0.as_ref()}}
impl ReadDM {
    pub async fn new(resolver: &mut dyn DidResolver, secret: impl DidSecret, since: i64) -> Result<Self, did::Error> {
        let secret = Box::new(secret) as Box<dyn DidSecret>;
        let time = Utc::now().timestamp();
        let did = secret.did();
        let signature = resolver.sign(secret.clone(), &[time.to_le_bytes(), since.to_le_bytes()].concat()).await?;
        Ok(ReadDM(Request::ReadDM(did, signature, time, since).into(), secret))
    }
}
impl RequestTrait for ReadDM {
    type Output = Result<ReadDMResult, Error>;

    fn process(self, response: Result<ChandlerResponse, Error>) -> Self::Output {
        let key = self.1.key("easy_access_com")?;
        match self.0.process(response)? {
            Response::ReadDM(items) => Ok(ReadDMResult(items.into_iter().flat_map(|item| {
                serde_json::from_slice::<(Did, Signature, Vec<u8>)>(&key.easy_decrypt(&item).ok()?).ok()
            }).collect())),
            res => Err(mr(res))
        }
    }
}
