use rusqlite::{OptionalExtension, Connection, params};
use serde::{Serialize, Deserialize};
use secp256k1::PublicKey;
use std::path::PathBuf;

use crate::server::Service;
use crate::did::{DidResolver, Signature, Did, Error};
use easy_secp256k1::Signed as KeySigned;
use chrono::Utc;

use super::{NAME, PrivateItem};

#[derive(Serialize, Deserialize, Clone, Debug, Hash)]
pub struct Catalog {
    //cost_per_read: u32,
}

#[derive(Serialize, Deserialize, Clone, Debug, Hash)]
pub enum Request{
    CreatePrivate(KeySigned<PrivateItem>),//Discover Signed Item
    ReadPrivate(KeySigned<()>),//Signed Discover, Include Size Limit?
    UpdatePrivate(KeySigned<KeySigned<PrivateItem>>),//Discover Signed Delete Signed NewItem
    DeletePrivate(KeySigned<PublicKey>),//Delete Signed Discover

  //CreatePublic(Signed<PublicItem>),
  //ReadPublic(String),//Sqlite Query, Include limit?
  //UpdatePublic(Signed<PublicItem>),
  //DeletePublic(Signed<String>),

    CreateDM(Did, Vec<u8>),
    ReadDM(Did, Signature, i64, i64)
}

#[derive(Serialize, Deserialize, Default, Clone, Debug, Hash)]
pub enum Response {
    InvalidRequest(String),
    InvalidSignature(String),
    InvalidDelete(Option<PublicKey>),
    ReadPrivate(Option<KeySigned<PrivateItem>>),
    PrivateConflict(KeySigned<PrivateItem>),
  //ReadPublic(Vec<(Signed<PublicItem>, DateTime::<Utc>)>),
  //PublicConflict(Signed<PublicItem>),
    ReadDM(Vec<Vec<u8>>),
    #[default]
    Empty,
}

#[async_trait::async_trait(?Send)]
impl Service for StorageService {
    fn name(&self) -> String {NAME.to_string()}
    fn catalog(&self) -> String {serde_json::to_string(&Catalog{}).unwrap()}
    async fn process(&mut self, resolver: &mut dyn DidResolver, request: String) -> String {
        let response = match serde_json::from_str(&request) {
            Ok(request) => self._process(resolver, request).await,
            Err(e) => Response::InvalidRequest(e.to_string())
        };
        serde_json::to_string(&response).unwrap()
    }
}

pub struct StorageService(Connection);
impl StorageService {
    pub async fn new(
        path: Option<PathBuf>,
    ) -> Result<Self, rusqlite::Error> {
        let database = Connection::open(path.unwrap_or(PathBuf::from(NAME)))?;
        database.execute("CREATE TABLE if not exists private(discover TEXT NOT NULL UNIQUE, del TEXT, payload BLOB NOT NULL);", [])?;
        database.execute("CREATE TABLE if not exists dms(recipient TEXT NOT NULL, payload BLOB NOT NULL, timestamp INTERGER NOT NULL);", [])?;
        Ok(StorageService(database))
    }

    async fn _process(&self, resolver: &mut dyn DidResolver, request: Request) -> Response {
        match request {
            Request::CreatePrivate(signed) => {
                match signed.verify() {
                    Ok(discover) => {
                        if discover != signed.as_ref().discover {return Response::InvalidRequest("Discover key mismatch between Signature and Payload".to_string());}
                        if let Some(conflict) = self.0.query_row(&format!("SELECT * FROM private WHERE discover='{}'", discover),
                            [], |r| Ok(serde_json::from_slice(&r.get::<&str, Vec<u8>>("payload")?).unwrap())
                        ).optional().unwrap() {
                            Response::PrivateConflict(conflict)
                        } else {
                            self.0.execute(
                                "INSERT INTO private(discover, del, payload) VALUES (?1, ?2, ?3);",
                                params![discover.to_string(), signed.as_ref().delete.map(|d| d.to_string()), serde_json::to_vec(&signed).unwrap()]
                            ).unwrap();
                            Response::Empty
                        }
                    },
                    Err(e) => Response::InvalidSignature(e.to_string())
                }
            },
            Request::ReadPrivate(signed) => {
                match signed.verify() {
                    Ok(discover) => Response::ReadPrivate(
                        self.0.query_row(&format!("SELECT * FROM private WHERE discover='{}'", discover),
                            [], |r| Ok(serde_json::from_slice(&r.get::<&str, Vec<u8>>("payload")?).unwrap())
                        ).optional().unwrap()
                    ),
                    Err(e) => Response::InvalidSignature(e.to_string())
                }
            },
            Request::UpdatePrivate(signed) => {
                match signed.verify() {
                    Ok(delete) => match signed.as_ref().verify() {
                        Ok(discover) => {
                            let old_item: Option<KeySigned<PrivateItem>> = self.0.query_row(&format!("SELECT * FROM private WHERE discover='{}'", discover),
                                [], |r| Ok(serde_json::from_slice(&r.get::<&str, Vec<u8>>("payload")?).unwrap())
                            ).optional().unwrap();
                            if let Some(old_signed) = old_item {
                                if Some(delete) != old_signed.as_ref().delete {
                                    return Response::InvalidDelete(old_signed.as_ref().delete);
                                }
                                self.0.execute("DELETE FROM private WHERE discover=?1;", [discover.to_string()]).unwrap();
                            }
                            self.0.execute(
                                "INSERT INTO private(discover, del, payload) VALUES (?1, ?2, ?3);",
                                params![discover.to_string(), signed.as_ref().as_ref().delete.map(|d| d.to_string()), serde_json::to_vec(signed.as_ref()).unwrap()]
                            ).unwrap();
                            Response::Empty
                        },
                        Err(e) => Response::InvalidSignature(e.to_string())
                    },
                    Err(e) => Response::InvalidSignature(e.to_string())
                }
            },
            Request::DeletePrivate(signed) => {
                match signed.verify() {
                    Ok(delete) => {
                        let discover = signed.as_ref();
                        let old_item: Option<KeySigned<PrivateItem>> = self.0.query_row(&format!("SELECT * FROM private WHERE discover='{}'", discover),
                            [], |r| Ok(serde_json::from_slice(&r.get::<&str, Vec<u8>>("payload")?).unwrap())
                        ).optional().unwrap();
                        if let Some(old_signed) = old_item {
                            if Some(delete) != old_signed.as_ref().delete {
                                return Response::InvalidDelete(old_signed.as_ref().delete);
                            }
                            self.0.execute("DELETE FROM private WHERE discover=?1;", [discover.to_string()]).unwrap();
                        }
                        Response::Empty
                    },
                    Err(e) => Response::InvalidSignature(e.to_string())
                }
            },
          //DwnRequest::CreatePublic(item) => {
          //    if item.0.verify(&*self.did_resolver, None).await.is_ok() {
          //        if let Some(item) = self.public_database.get::<PublicDwnItem>(&item.primary_key()).await? {
          //            return Ok(DwnResponse::PublicConflict(item));
          //        }
          //        self.public_database.set(&item).await?;
          //        DwnResponse::Empty
          //    } else {DwnResponse::InvalidAuth("Signature".to_string())}
          //},
          //DwnRequest::ReadPublic(filters, sort_options) => {
          //    DwnResponse::ReadPublic(self.public_database.query::<PublicDwnItem>(&filters, sort_options).await?.0)
          //},
          //DwnRequest::UpdatePublic(item) => {
          //    if let Ok(verifier) = item.0.verify(&*self.did_resolver, None).await {
          //        if let Some(oitem) = self.public_database.get::<PublicDwnItem>(&item.primary_key()).await? {
          //            if verifier != *oitem.0.signer() {
          //                return Ok(DwnResponse::InvalidAuth("Signature".to_string()));
          //            }
          //        }
          //        self.public_database.set(&item).await?;
          //        DwnResponse::Empty
          //    } else {DwnResponse::InvalidAuth("Signature".to_string())}
          //},
          //DwnRequest::DeletePublic(req) => {
          //    if let Ok(verifier) = req.verify(&*self.did_resolver, None).await {
          //        if let Some(item) = self.public_database.get::<PublicDwnItem>(req.inner().as_bytes()).await? {
          //            if verifier != *item.0.signer() {
          //                return Ok(DwnResponse::InvalidAuth("Signature".to_string()));
          //            }
          //        }
          //        DwnResponse::Empty
          //    } else {DwnResponse::InvalidAuth("Signature".to_string())}
          //},
            Request::CreateDM(recipient, payload) => {
                self.0.execute(
                    "INSERT INTO dms(recipient, payload, timestamp) VALUES (?1, ?2, ?3);",
                    params![recipient.to_string(), payload, Utc::now().timestamp()]
                ).unwrap();
                Response::Empty
            },
            Request::ReadDM(did, signature, time, since) => {
                let now = Utc::now().timestamp();
                match resolver.verify(&did, &signature, &[time.to_le_bytes(), since.to_le_bytes()].concat(), None).await {
                    Ok(_) => match time <= now && time >= now-10_000 {
                        true => {
                            let mut stmt = self.0.prepare(&format!("SELECT payload FROM dms WHERE recipient='{}' AND timestamp >= {}", did, since)).unwrap();
                            self.0.execute(
                                "INSERT OR REPLACE INTO read_dms(recipient, timestamp) VALUES (?1, ?2);",
                                params![did.to_string(), Utc::now().timestamp()]
                            ).unwrap();
                            Response::ReadDM(stmt.query_map([], |r| r.get(0)).unwrap().collect::<Result<Vec<_>, rusqlite::Error>>().unwrap())
                        },
                        false => Response::InvalidSignature("Expired".to_string())
                    },
                    Err(Error::Critical(e)) => panic!("{:?}", e),
                    Err(e) => Response::InvalidSignature(e.to_string())
                }
            }
        }
    }
}
