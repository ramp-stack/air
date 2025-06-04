use rusqlite::{OptionalExtension, Connection, params};
use std::path::PathBuf;
use std::str::FromStr;

use crate::server::Service as ServiceTrait;
use crate::orange_name::{OrangeResolver, OrangeName, Signed as DidSigned, Error};
use easy_secp256k1::Signed as KeySigned;
use crate::{DateTime, Id, now};

use super::{NAME, Catalog, Request, Response, PrivateItem, PublicItem, Op};

#[async_trait::async_trait(?Send)]
impl ServiceTrait for Service {
    fn name(&self) -> String {NAME.to_string()}
    fn catalog(&self) -> String {serde_json::to_string(&Catalog{}).unwrap()}
    async fn process(&mut self, resolver: &mut OrangeResolver, request: String) -> String {
        let response = match serde_json::from_str(&request) {
            Ok(request) => self._process(resolver, request).await,
            Err(e) => Response::InvalidRequest(e.to_string())
        };
        serde_json::to_string(&response).unwrap()
    }
}

pub struct Service(Connection);
impl Service {
    pub async fn new(
        path: Option<PathBuf>,
    ) -> Result<Self, rusqlite::Error> {
        let database = Connection::open(path.unwrap_or(PathBuf::from(NAME)))?;
        database.execute("CREATE TABLE if not exists public(
            id TEXT NOT NULL UNIQUE,
            signer TEXT NOT NULL,
            protocol TEXT NOT NULL,
            timestamp INTERGER NOT NULL,
            payload BLOB NOT NULL
        );", [])?;
        database.execute("CREATE TABLE if not exists private(discover TEXT NOT NULL UNIQUE, del TEXT, payload BLOB NOT NULL, timestamp INTERGER NOT NULL);", [])?;
        database.execute("CREATE TABLE if not exists dms(recipient TEXT NOT NULL, payload BLOB NOT NULL, timestamp INTERGER NOT NULL);", [])?;
        Ok(Service(database))
    }

    async fn _process(&self, resolver: &mut OrangeResolver, request: Request) -> Response {
        match request {
            Request::CreatePrivate(signed) => {
                match signed.verify() {
                    Ok(discover) => {
                        if discover != signed.as_ref().discover {return Response::InvalidRequest("Discover key mismatch between Signature and Payload".to_string());}
                        if let Some((conflict, datetime)) = self.0.query_row(&format!("SELECT * FROM private WHERE discover='{}'", discover),
                            [], |r| Ok((serde_json::from_slice(&r.get::<&str, Vec<u8>>("payload")?).unwrap(), r.get::<&str, i64>("timestamp")?))
                        ).optional().unwrap() {
                            Response::PrivateConflict(conflict, DateTime::from_timestamp(datetime, 0).unwrap())
                        } else {
                            self.0.execute(
                                "INSERT INTO private(discover, del, payload, timestamp) VALUES (?1, ?2, ?3, ?4);",
                                params![discover.to_string(), signed.as_ref().delete.map(|d| d.to_string()), serde_json::to_vec(&signed).unwrap(), now().timestamp()]
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
                            [], |r| Ok((serde_json::from_slice(&r.get::<&str, Vec<u8>>("payload")?).unwrap(), r.get::<&str, i64>("timestamp")?))
                        ).optional().unwrap().map(|(i, d)| (i, DateTime::from_timestamp(d, 0).unwrap()))
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
                                "INSERT INTO private(discover, del, payload, timestamp) VALUES (?1, ?2, ?3, ?4);",
                                params![
                                    discover.to_string(), signed.as_ref().as_ref().delete.map(|d| d.to_string()),
                                    serde_json::to_vec(signed.as_ref()).unwrap(), now().timestamp()
                                ]
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
            Request::CreatePublic(signed) => {
                match signed.verify(resolver, None).await {
                    Ok(signer) => {
                        let id = Id::random();
                        self.0.execute(
                            "INSERT INTO public(id, signer, protocol, timestamp, payload) VALUES (?1, ?2, ?3, ?4, ?5);",
                            params![id.to_string(), signer.to_string(), signed.as_ref().protocol.to_string(), now().timestamp(), serde_json::to_vec(&signed).unwrap()]
                        ).unwrap();
                        Response::CreatedPublic(id)
                    },
                    Err(e) => Response::InvalidSignature(e.to_string())
                }
            },
            Request::ReadPublic(filter) => {
                let mut first = false;
                let query = format!("SELECT * FROM public{}{}{}{}",
                    filter.id.map(|i| {first = true; format!(" WHERE id='{}'", i)}).unwrap_or("".to_string()),
                    filter.author.map(|a| {let r = format!(" {}signer='{}'", if first {"AND "} else {"WHERE "}, a); first = true; r}).unwrap_or("".to_string()),
                    filter.protocol.map(|p| {let r = format!(" {}protocol='{}'", if first {"AND "} else {"WHERE "}, p); first = true; r}).unwrap_or("".to_string()),
                    filter.datetime.map(|(op, d)| {
                        let r = format!(" {}timestamp{}", if first {"AND "} else {"WHERE "}, match op {
                            Op::LS => format!("<{}", d.timestamp()),
                            Op::LSE => format!("<={}", d.timestamp()),
                            Op::E => format!("={}", d.timestamp()),
                            Op::GRE => format!(">={}", d.timestamp()),
                            Op::GR => format!(">{}", d.timestamp()),
                        });
                        first = true;
                        r
                    }).unwrap_or("".to_string())
                );
                println!("Query: {}", query);
                let mut stmt = self.0.prepare(&query).unwrap();
                Response::ReadPublic(stmt.query_map([], |r| Ok((
                    Id::from_str(&r.get::<&str, String>("id")?).unwrap(),
                    serde_json::from_slice::<DidSigned<PublicItem>>(&r.get::<&str, Vec<u8>>("payload")?).unwrap(),
                    DateTime::from_timestamp(r.get(3)?, 0).unwrap()
                ))).unwrap().collect::<Result<Vec<_>, rusqlite::Error>>().unwrap())
            },
            Request::UpdatePublic(signed) => match signed.verify(resolver, None).await {
                Ok(author) => {
                    let (id, payload) = signed.into_inner();
                    match payload.verify(resolver, None).await {
                        Ok(author2) if author == author2 => match self.0.query_row(&format!("SELECT signer FROM public WHERE id='{}'", id),
                                [], |r| Ok(OrangeName::from_str(&r.get::<&str, String>("signer")?).unwrap())
                        ).optional().unwrap() {
                            Some(author3) if author2 == author3 => {
                                self.0.execute("DELETE FROM public WHERE id=?1;", [id.to_string()]).unwrap();
                                self.0.execute(
                                    "INSERT INTO public(id, signer, protocol, timestamp, payload) VALUES (?1, ?2, ?3, ?4, ?5);",
                                    params![id.to_string(), author3.to_string(), payload.as_ref().protocol.to_string(), now().timestamp(), serde_json::to_vec(&payload).unwrap()]
                                ).unwrap();
                                Response::Empty
                            },
                            Some(_) => Response::InvalidSignature("Signer dose not match current author".to_string()),
                            None => {
                                self.0.execute(
                                    "INSERT INTO public(id, signer, protocol, timestamp, payload) VALUES (?1, ?2, ?3, ?4, ?5);",
                                    params![id.to_string(), author2.to_string(), payload.as_ref().protocol.to_string(), now().timestamp(), serde_json::to_vec(&payload).unwrap()]
                                ).unwrap();
                                Response::Empty
                            }
                        },
                        Ok(_) => Response::InvalidSignature("Signers do not match".to_string()),
                        Err(e) => Response::InvalidSignature(e.to_string())
                    }
                },
                Err(e) => Response::InvalidSignature(e.to_string())
            },
            Request::DeletePublic(signed) => match signed.verify(resolver, None).await {
                Ok(author) => {
                    let id = signed.into_inner();
                    match self.0.query_row(&format!("SELECT signer FROM public WHERE id='{}'", id),
                            [], |r| Ok(OrangeName::from_str(&r.get::<&str, String>("signer")?).unwrap())
                    ).optional().unwrap() {
                        Some(author2) if author == author2 => {
                            self.0.execute("DELETE FROM public WHERE id=?1;", [id.to_string()]).unwrap();
                            Response::Empty
                        },
                        Some(_) => Response::InvalidSignature("Signer dose not match current author".to_string()),
                        None => Response::Empty
                    }
                },
                Err(e) => Response::InvalidSignature(e.to_string())
            },
            Request::CreateDM(recipient, payload) => {
                self.0.execute(
                    "INSERT INTO dms(recipient, payload, timestamp) VALUES (?1, ?2, ?3);",
                    params![recipient.to_string(), payload, now().timestamp()]
                ).unwrap();
                Response::Empty
            },
            Request::ReadDM(signed) => {
                let now = now().timestamp();
                let time = signed.as_ref().0.timestamp();
                let since = signed.as_ref().1.timestamp();
                match signed.verify(resolver, None).await {
                    Ok(name) => match time <= now && time >= now-10_000 {
                        true => {
                            let mut stmt = self.0.prepare(&format!("SELECT payload FROM dms WHERE recipient='{}' AND timestamp >= {}", name, since)).unwrap();
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
