use secp256k1::{SecretKey, PublicKey};
use easy_secp256k1::{EasySecretKey, EasyPublicKey};
use serde::{Serialize, Deserialize};

use super::{Request, PrivateItem, PublicItem, Filter};
use crate::server::{Error, Context, Command};
use crate::{Id, DateTime, now};

use orange_name::{self, OrangeResolver, OrangeSecret, OrangeName, Signed as DidSigned, Endpoint};

#[derive(Serialize, Deserialize)]
pub struct CreatePrivate(Request, Endpoint);
impl CreatePrivate {
    pub fn new(sdiscover: &SecretKey, delete: Option<PublicKey>, header: Vec<u8>, payload: Vec<u8>, endpoint: Endpoint) -> Self {
        CreatePrivate(Request::create_private(sdiscover, delete, header, payload), endpoint)
    }
}
impl Command for CreatePrivate {
    type Output = Result<Option<DateTime>, Error>;

    async fn run(self, mut ctx: Context) -> Self::Output {
        ctx.run((self.0, self.1)).await?.create_private()
    }
}

#[derive(Serialize, Deserialize)]
pub struct ReadPrivate(Request, PublicKey, Endpoint);
impl ReadPrivate {
    pub fn new(sec_discover: &SecretKey, endpoint: Endpoint) -> Self {
        ReadPrivate(Request::read_private(sec_discover), sec_discover.easy_public_key(), endpoint)
    }
}
impl Command for ReadPrivate {
    type Output = Result<Option<(DateTime, Option<PrivateItem>)>, Error>;

    async fn run(self, mut ctx: Context) -> Self::Output {
        ctx.run((self.0, self.2)).await?.read_private().map(|r| r.map(|(d, r)| (d, r.and_then(|signed| (
            *signed.signer() == self.1 && signed.verify().is_ok() && signed.as_ref().discover == self.1 
        ).then_some(signed.into_inner())))))
    }
}

#[derive(Serialize, Deserialize)]
pub struct ReadPrivateHeader(Request, PublicKey, Endpoint);
impl ReadPrivateHeader {
    pub fn new(sec_discover: &SecretKey, endpoint: Endpoint) -> Self {
        ReadPrivateHeader(Request::read_private_header(sec_discover), sec_discover.easy_public_key(), endpoint)
    }
}
impl Command for ReadPrivateHeader {
    type Output = Result<Option<(DateTime, Option<Vec<u8>>)>, Error>;

    async fn run(self, mut ctx: Context) -> Self::Output {
        ctx.run((self.0, self.2)).await?.read_private_header().map(|r| r.map(|(date,  signed)|
            (date, (*signed.signer() == self.1 && signed.verify().is_ok()).then_some(signed.into_inner()))
        ))
    }
}


#[derive(Serialize, Deserialize)]
pub struct DeletePrivate(Request, PublicKey, Endpoint);
impl DeletePrivate {
    pub fn new(discover: PublicKey, delete: &SecretKey, endpoint: Endpoint) -> Self {
        DeletePrivate(Request::delete_private(discover, delete), delete.easy_public_key(), endpoint)
    }
}
impl Command for DeletePrivate {
    type Output = Result<Option<Option<PublicKey>>, Error>;

    async fn run(self, mut ctx: Context) -> Self::Output {
        match ctx.run((self.0, self.2)).await?.delete_private()? {
            Some(key) if key != Some(self.1) => Ok(Some(key)),
            None => Ok(None),
            r => Err(Error::mr(r))
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct CreateDM{
    secret: OrangeSecret, recipient: OrangeName, payload: Vec<u8>, endpoint: Endpoint
}
impl CreateDM {
    pub fn new(secret: OrangeSecret, recipient: OrangeName, payload: Vec<u8>, endpoint: Endpoint) -> Self {
        CreateDM{secret, recipient, payload, endpoint}
    }
}
impl Command for CreateDM {
    type Output = Result<(), Error>;

    async fn run(self, mut ctx: Context) -> Self::Output {
        let mut resolver = ctx.get_mut_or_default::<OrangeResolver>().await;
        let com = resolver.key(&self.recipient, Some("easy_access_com"), None).await?;
        let signed = DidSigned::new(&mut resolver, &self.secret, self.payload).await?;
        drop(resolver);
        ctx.run((Request::create_dm(
            self.recipient, com.easy_encrypt(serde_json::to_vec(&signed).unwrap()).unwrap()
        ), self.endpoint)).await?.create_dm()
    }
}

#[derive(Serialize, Deserialize)]
pub struct ReadDM(OrangeSecret, DateTime, Endpoint);
impl ReadDM {
    pub fn new(secret: OrangeSecret, since: DateTime, endpoint: Endpoint) -> Self {
        ReadDM(secret, since, endpoint)
    }
}
impl Command for ReadDM {
    type Output = Result<Vec<(OrangeName, Vec<u8>)>, Error>;

    async fn run(self, mut ctx: Context) -> Self::Output {
        let mut resolver = ctx.get_mut_or_default::<OrangeResolver>().await;
        let signed = DidSigned::new(&mut resolver, &self.0, (now(), self.1)).await?;
        drop(resolver);
        let items = ctx.run((Request::ReadDM(signed), self.2)).await?.read_dm()?;

        let mut resolver = ctx.get_mut_or_default::<OrangeResolver>().await;
        let key = resolver.secret_key(&self.0, Some("easy_access_com"), None).await?;
        let items = items.into_iter().flat_map(|item| {
            serde_json::from_slice::<DidSigned<Vec<u8>>>(&key.easy_decrypt(&item).ok()?).ok()
        }).collect::<Vec<_>>();

        let mut results = Vec::new();
        for signed in items {
            if signed.verify(&mut resolver, None).await.is_ok() {
                results.push((signed.signer().clone(), signed.into_inner()));
            }
        }
        Ok(results)
    }
}

#[derive(Serialize, Deserialize)]
pub struct CreatePublic(OrangeSecret, PublicItem, Endpoint);
impl CreatePublic {
    pub fn new(secret: OrangeSecret, item: PublicItem, endpoint: Endpoint) -> Self {
        CreatePublic(secret, item, endpoint)
    }
}
impl Command for CreatePublic {
    type Output = Result<Id, Error>;

    async fn run(self, mut ctx: Context) -> Self::Output {
        let mut resolver = ctx.get_mut_or_default::<OrangeResolver>().await;
        let signed = DidSigned::new(&mut resolver, &self.0, self.1).await?;
        drop(resolver);
        ctx.run((Request::CreatePublic(signed), self.2)).await?.create_public()
    }
}


#[derive(Serialize, Deserialize)]
pub struct ReadPublic(Request, Filter, Endpoint);
impl ReadPublic {
    pub fn new(filter: Filter, endpoint: Endpoint) -> Self {
        ReadPublic(Request::ReadPublic(filter.clone()), filter, endpoint)
    }
}
impl Command for ReadPublic {
    type Output = Result<Vec<(Id, OrangeName, PublicItem, DateTime)>, Error>;

    async fn run(self, mut ctx: Context) -> Self::Output {
        let items = ctx.run((self.0, self.2)).await?.read_public()?;
        let mut resolver = ctx.get_mut_or_default::<OrangeResolver>().await;
        let mut results = Vec::new();
        for (id, signed, date) in items {
            let name = signed.verify(&mut resolver, Some(date)).await.map_err(Error::mr)?;
            if self.1.filter(&id, &name, signed.as_ref(), &date) {
                results.push((id, name, signed.into_inner(), date));
            }
        }
        Ok(results)
    }
}

#[derive(Serialize, Deserialize)]
pub struct UpdatePublic(OrangeSecret, Id, PublicItem, Endpoint);
impl UpdatePublic {
    pub fn new(secret: OrangeSecret, id: Id, item: PublicItem, endpoint: Endpoint) -> Self {
        UpdatePublic(secret, id, item, endpoint)
    }
}
impl Command for UpdatePublic {
    type Output = Result<(), Error>;

    async fn run(self, mut ctx: Context) -> Self::Output {
        let mut resolver = ctx.get_mut_or_default::<OrangeResolver>().await;
        let signed = DidSigned::new(&mut resolver, &self.0, self.2).await?;
        let signed = DidSigned::new(&mut resolver, &self.0, (self.1, signed)).await?;
        drop(resolver);
        ctx.run((Request::UpdatePublic(signed), self.3)).await?.update_public()
    }
}

#[derive(Serialize, Deserialize)]
pub struct DeletePublic(OrangeSecret, Id, Endpoint);
impl DeletePublic {
    pub fn new(secret: OrangeSecret, id: Id, endpoint: Endpoint) -> Self {
        DeletePublic(secret, id, endpoint)
    }
}
impl Command for DeletePublic {
    type Output = Result<(), Error>;

    async fn run(self, mut ctx: Context) -> Self::Output {
        let mut resolver = ctx.get_mut_or_default::<OrangeResolver>().await;
        let signed = DidSigned::new(&mut resolver, &self.0, self.1).await?;
        drop(resolver);
        ctx.run((Request::DeletePublic(signed), self.2)).await?.delete_public()
    }
}
