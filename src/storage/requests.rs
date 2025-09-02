use secp256k1::{SecretKey, PublicKey};
use easy_secp256k1::EasySecretKey;
use serde::{Serialize, Deserialize};

use super::{Request, Response, PrivateItem, NAME, PublicItem, Filter};
use crate::server::{Request as ChandlerRequest, Response as ChandlerResponse, Error, Context, Command};
use crate::{Id, DateTime};

use crate::orange_name::{self, OrangeResolver, OrangeSecret, OrangeName, Signed as DidSigned, Endpoint};

//  pub struct MajorityResponse<C>(Vec<C>);
//  impl<C: Command<Output: PartialEq>> Command for MajorityResponse<C> {
//      type Output = Option<C::Output>;

//      async fn run(self, mut ctx: Context) -> Self::Output {
//          let req = (self.0.len() / 2) + 1;
//          let responses: Vec<C::Output> = ctx.run(self.0).await;
//          let (count, winner) = responses.into_iter().fold((0, None), |mut acc, p| {
//              if acc.0 == 0 {acc.1 = Some(p);}
//              else if acc.1 == Some(p) {acc.0 += 1;}
//              else {acc.0 -= 1;}
//              acc
//          });
//          if count >= req {Some(winner.unwrap())} else {None}
//      }
//  }


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

#[derive(Serialize, Deserialize)]
pub struct CreateDM(Request, Endpoint);
impl CreateDM {
    pub async fn new(resolver: &mut OrangeResolver, secret: &OrangeSecret, recipient: OrangeName, payload: Vec<u8>, endpoint: Endpoint) -> Result<Self, Error> {
        Ok(CreateDM(Request::create_dm(resolver, secret, recipient, payload).await?, endpoint))
    }
}
impl Command for CreateDM {
    type Output = Result<(), Error>;

    async fn run(self, mut ctx: Context) -> Self::Output {
        ctx.run((self.0, self.1)).await?.create_dm()
    }
}

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
        let resolver = ctx.get_mut_or_default::<OrangeResolver>().await;
        let key = resolver.secret_keys(&self.1, Some("easy_access_com"), None).await?.first()
            .ok_or(orange_name::Error::Resolution("Could not find easy_access_com key".to_string()))?.1;
        let items = items.into_iter().flat_map(|item| {
            serde_json::from_slice::<DidSigned<Vec<u8>>>(&key.easy_decrypt(&item).ok()?).ok()
        }).collect::<Vec<_>>();

        let mut results = Vec::new();
        for signed in items {
            match signed.verify(resolver, None).await {
                Err(e) if e.is_critical() => {return Err(e.into());},
                Err(_) => {},
                Ok(name) => {results.push((name, signed.into_inner()));}
            }
        }
        Ok(results)
    }
}

#[derive(Serialize, Deserialize)]
pub struct CreatePublic(Request, Endpoint);
impl CreatePublic {
    pub async fn new(resolver: &mut OrangeResolver, secret: &OrangeSecret, item: PublicItem, endpoint: Endpoint) -> Result<Self, Error> {
        Ok(CreatePublic(Request::create_public(resolver, secret, item).await?, endpoint))
    }
}
impl Command for CreatePublic {
    type Output = Result<Id, Error>;

    async fn run(self, mut ctx: Context) -> Self::Output {
        ctx.run((self.0, self.1)).await?.create_public()
    }
}

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
        let resolver = ctx.get_mut_or_default::<OrangeResolver>().await;
        let mut results = Vec::new();
        for (id, signed, date) in items {
            let name = signed.verify(resolver, Some(date)).await.map_err(Error::mr)?;
            if self.1.filter(&id, &name, signed.as_ref(), &date) {
                results.push((id, name, signed.into_inner(), date));
            }
        }
        Ok(results)
    }
}

#[derive(Serialize, Deserialize)]
pub struct UpdatePublic(Request, Endpoint);
impl UpdatePublic {
    pub async fn new(resolver: &mut OrangeResolver, secret: &OrangeSecret, id: Id, item: PublicItem, endpoint: Endpoint) -> Result<Self, Error> {
        Ok(UpdatePublic(Request::update_public(resolver, secret, id, item).await?, endpoint))
    }
}
impl Command for UpdatePublic {
    type Output = Result<(), Error>;

    async fn run(self, mut ctx: Context) -> Self::Output {
        ctx.run((self.0, self.1)).await?.update_public()
    }
}

#[derive(Serialize, Deserialize)]
pub struct DeletePublic(Request, Endpoint);
impl DeletePublic {
    pub async fn new(resolver: &mut OrangeResolver, secret: &OrangeSecret, id: Id, endpoint: Endpoint) -> Result<Self, Error> {
        Ok(DeletePublic(Request::delete_public(resolver, secret, id).await?, endpoint))
    }
}
impl Command for DeletePublic {
    type Output = Result<(), Error>;

    async fn run(self, mut ctx: Context) -> Self::Output {
        ctx.run((self.0, self.1)).await?.delete_public()
    }
}

        
//  #[derive(Debug)]
//  enum MidState {
//      Secret(OrangeSecret),
//      Filter(Filter),
//      Key(PublicKey),
//      Empty,
//  }

//  #[allow(clippy::large_enum_variant)]
//  #[derive(Serialize, Deserialize, Debug)]
//  pub enum Processed {
//      CreatePublic(Id),
//      PrivateItem(Option<(DateTime, Option<PrivateItem>)>),
//      PrivateHeader(Option<(DateTime, Option<Vec<u8>>)>),
//      PrivateCreate(Option<DateTime>),
//      ReadPublic(Vec<(Id, OrangeName, PublicItem, DateTime)>),
//      DeleteKey(Option<PublicKey>),
//      ReadDM(Vec<(OrangeName, Vec<u8>)>),
//      Empty
//  }

//  pub struct Client(Request, MidState);
//  impl Client {
//      pub fn create_private(sec_discover: &SecretKey, delete: Option<PublicKey>, header: Vec<u8>, payload: Vec<u8>) -> Self {
//          let discover = sec_discover.easy_public_key();
//          Client(Request::create_private(sec_discover, delete, header, payload), MidState::Key(discover))
//      }
//      pub fn read_private_header(sec_discover: &SecretKey) -> Self {
//          let discover = sec_discover.easy_public_key();
//          Client(Request::read_private_header(sec_discover), MidState::Key(discover))
//      }
//      pub fn read_private(sec_discover: &SecretKey) -> Self {
//          let discover = sec_discover.easy_public_key();
//          Client(Request::read_private(sec_discover), MidState::Key(discover))
//      }
//    //pub fn update_private(discover: &SecretKey, delete: &SecretKey, header: Vec<u8>, payload: Vec<u8>) -> Self {
//    //    Client(Request::update_private(discover, delete, header, payload), MidState::Key(delete.easy_public_key()))
//    //}

//      pub fn delete_private(discover: PublicKey, delete: &SecretKey) -> Self {
//          Client(Request::delete_private(discover, delete), MidState::Key(delete.easy_public_key()))
//      }

//      pub async fn create_dm(resolver: &mut OrangeResolver, secret: &OrangeSecret, recipient: OrangeName, payload: Vec<u8>) -> Result<Self, Error> {
//          Ok(Client(Request::create_dm(resolver, secret, recipient, payload).await?, MidState::Empty))
//      }
//      pub async fn read_dm(resolver: &mut OrangeResolver, secret: &OrangeSecret, since: DateTime) -> Result<Self, Error> {
//          Ok(Client(Request::read_dm(resolver, secret, since).await?, MidState::Secret(secret.clone())))
//      }
//      pub async fn create_public(resolver: &mut OrangeResolver, secret: &OrangeSecret, item: PublicItem) -> Result<Self, Error> {
//          Ok(Client(Request::create_public(resolver, secret, item).await?, MidState::Empty))
//      }
//      pub fn read_public(filter: Filter) -> Self {Client(Request::ReadPublic(filter.clone()), MidState::Filter(filter))}
//      pub async fn update_public(resolver: &mut OrangeResolver, secret: &OrangeSecret, id: Id, item: PublicItem) -> Result<Self, Error> {
//          Ok(Client(Request::update_public(resolver, secret, id, item).await?, MidState::Empty))
//      }
//      pub async fn delete_public(resolver: &mut OrangeResolver, secret: &OrangeSecret, id: Id) -> Result<Self, Error> {
//          Ok(Client(Request::delete_public(resolver, secret, id).await?, MidState::Empty))
//      }

//      pub fn build_request(&self) -> ChandlerRequest {
//          ChandlerRequest::Service(NAME.to_string(), serde_json::to_string(&self.0).unwrap())
//      }
//      pub async fn process_response(&self, resolver: &mut OrangeResolver, response: ChandlerResponse) -> Result<Processed, Error> {
//          Ok(match (&self.0, &self.1, response.service::<Request>()?) {
//              (Request::ReadPrivateHeader(_), MidState::Key(key), Response::ReadPrivateHeader(response)) =>
//                  Processed::PrivateHeader(response.map(|(d, r)| (d, r.and_then(|signed| (signed.signer() == key && signed.verify().is_ok()).then_some(signed.into_inner()))))),
//            //(Request::ReadPrivateHeader(_), MidState::Key(key), Response::ReadPrivateHeader(Some((signed, date)), exists))
//            //    if *signed.signer() == *key && signed.verify().is_ok() 
//            //        => Processed::PrivateHeader(Some((signed.into_inner(), date)), exists),
//              (Request::ReadPrivate(_), MidState::Key(key), Response::ReadPrivate(response)) => 
//                  Processed::PrivateItem(response.map(|(d, r)| (d, r.and_then(|signed| (signed.signer() == key && signed.verify().is_ok() && signed.as_ref().discover == *key).then_some(signed.into_inner()))))),

//            //(Request::ReadPrivate(_), MidState::Key(key), Response::ReadPrivate(Some((signed, date))))
//            //    if *signed.signer() == *key && signed.verify().is_ok() && signed.as_ref().discover == *key 
//            //        => Processed::PrivateItem(Box::new(Some((signed.into_inner(), date))), exists),
//            //(Request::ReadPrivate(_), MidState::Key(_), Response::ReadPrivate(None, exists)) => Processed::PrivateItem(Box::new(None), exists),
//              (Request::DeletePrivate(_), MidState::Key(_), Response::Empty) => Processed::DeleteKey(None),
//              (Request::DeletePrivate(_), MidState::Key(mkey), Response::InvalidDelete(key)) if key != Some(*mkey) => Processed::DeleteKey(key),
//              (Request::CreatePrivate(_), MidState::Empty, Response::CreatePrivate(date)) => Processed::PrivateCreate(date),
//              (Request::CreateDM(_, _), MidState::Empty, Response::Empty) => Processed::Empty,
//              (Request::ReadDM(_), MidState::Secret(secret), Response::ReadDM(items)) => {
//                  let key = resolver.secret_keys(secret, Some("easy_access_com"), None).await?.first()
//                      .ok_or(orange_name::Error::Resolution("Could not find easy_access_com key".to_string()))?.1;
//                  let items = items.into_iter().flat_map(|item| {
//                      serde_json::from_slice::<DidSigned<Vec<u8>>>(&key.easy_decrypt(&item).ok()?).ok()
//                  }).collect::<Vec<_>>();

//                  let mut results = Vec::new();
//                  for signed in items {
//                      match signed.verify(resolver, None).await {
//                          Err(e) if e.is_critical() => {return Err(e.into());},
//                          Err(_) => {},
//                          Ok(name) => {results.push((name, signed.into_inner()));}
//                      }
//                  }
//                  Processed::ReadDM(results)
//              },
//              (Request::CreatePublic(_), MidState::Empty, Response::CreatedPublic(id)) => Processed::CreatePublic(id),
//              (Request::ReadPublic(_), MidState::Filter(filter), Response::ReadPublic(items)) => {
//                  let mut results = Vec::new();
//                  for (id, signed, date) in items {
//                      let name = signed.verify(resolver, Some(date)).await.map_err(Error::mr)?;
//                      if filter.filter(&id, &name, signed.as_ref(), &date) {
//                          results.push((id, name, signed.into_inner(), date));
//                      } else {return Err(Error::mr("Item does not match filter"));}
//                  }
//                  Processed::ReadPublic(results)
//              },
//              (Request::UpdatePublic(_), MidState::Empty, Response::Empty) => Processed::Empty,
//              (Request::DeletePublic(_), MidState::Empty, Response::Empty) => Processed::Empty,
//              res => {return Err(Error::mr(res));}
//          })
//      }
//  }
