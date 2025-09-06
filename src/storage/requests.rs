use secp256k1::{SecretKey, PublicKey};
use easy_secp256k1::EasySecretKey;
use serde::{Serialize, Deserialize};

use super::{Request, PrivateItem, PublicItem, Filter};
use crate::server::{Error, Context, Command};
use crate::{Id, DateTime};

use crate::orange_name::{self, OrangeResolver, OrangeSecret, OrangeName, Signed as DidSigned, Endpoint};

macro_rules! async_passthrough {
    ($name:ident, $snake_name:ident, ($($param_names:tt)+): ($($params:tt)+) @ ($($output:tt)+)) => {
        #[derive(Serialize, Deserialize)]
        pub struct $name(Request, Endpoint);
        impl $name {
            pub async fn new($($params)+, endpoint: Endpoint) -> Result<Self, Error> {
                Ok($name(Request::$snake_name($($param_names)+).await?, endpoint))
            }
        }
        impl Command for $name {
            type Output = $($output)+;

            async fn run(self, mut ctx: Context) -> Self::Output {
                ctx.run((self.0, self.1)).await?.$snake_name()
            }
        }
    };
}

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
        ctx.run((self.0, self.2)).await?.read_private_header().map(|r| r.map(|(d, r)| (d, r.and_then(|signed| (
            *signed.signer() == self.1 && signed.verify().is_ok()
        ).then_some(signed.into_inner())))))
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

async_passthrough!(
    CreateDM, create_dm,
    (resolver, secret, recipient, payload): 
    (resolver: &mut OrangeResolver, secret: &OrangeSecret, recipient: OrangeName, payload: Vec<u8>) @
    (Result<(), Error>)
);

#[derive(Serialize, Deserialize)]
pub struct ReadDM(Request, OrangeSecret, Endpoint);
impl ReadDM {
    pub async fn new(resolver: &mut OrangeResolver, secret: &OrangeSecret, since: DateTime, endpoint: Endpoint) -> Result<Self, Error> {
        Ok(ReadDM(Request::read_dm(resolver, secret, since).await?, secret.clone(), endpoint))
    }
}
impl Command for ReadDM {
    type Output = Result<Vec<(OrangeName, Vec<u8>)>, Error>;

    async fn run(self, mut ctx: Context) -> Self::Output {
        let items = ctx.run((self.0, self.2)).await?.read_dm()?;
        let mut resolver = ctx.get_mut_or_default::<OrangeResolver>().await;
        let key = resolver.secret_keys(&self.1, Some("easy_access_com"), None).await?.first()
            .ok_or(orange_name::Error::Resolution("Could not find easy_access_com key".to_string()))?.1;
        let items = items.into_iter().flat_map(|item| {
            serde_json::from_slice::<DidSigned<Vec<u8>>>(&key.easy_decrypt(&item).ok()?).ok()
        }).collect::<Vec<_>>();

        let mut results = Vec::new();
        for signed in items {
            match signed.verify(&mut resolver, None).await {
                Err(e) if e.is_critical() => {return Err(e.into());},
                Err(_) => {},
                Ok(name) => {results.push((name, signed.into_inner()));}
            }
        }
        Ok(results)
    }
}

async_passthrough!(
    CreatePublic, create_public,
    (resolver, secret, item): 
    (resolver: &mut OrangeResolver, secret: &OrangeSecret, item: PublicItem) @
    (Result<Id, Error>)
);


#[derive(Serialize, Deserialize)]
pub struct ReadPublic(Request, Filter, Endpoint);
impl ReadPublic {
    pub fn new(filter: Filter, endpoint: Endpoint) -> Self {
        ReadPublic(Request::read_public(filter.clone()), filter, endpoint)
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

async_passthrough!(
    UpdatePublic, update_public,
    (resolver, secret, id, item): 
    (resolver: &mut OrangeResolver, secret: &OrangeSecret, id: Id, item: PublicItem) @
    (Result<(), Error>)
);

async_passthrough!(
    DeletePublic, delete_public,
    (resolver, secret, id): 
    (resolver: &mut OrangeResolver, secret: &OrangeSecret, id: Id) @
    (Result<(), Error>)
);
