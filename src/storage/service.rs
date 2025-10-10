use rusqlite::Connection;
use std::collections::BTreeMap;
use std::path::PathBuf;

use crate::server::Service as ServiceTrait;
use crate::{DateTime, now};

use super::{Catalog, Request, Response, PrivateItem};

use serde::{Serialize, Deserialize};
use orange_name::{Resolver, Secret, secp256k1::{PublicKey, Signed as KeySigned}, Id};

use active_rusqlite::*;

#[derive(Serialize, Deserialize, ActiveRecord)]
#[active_record(children)]
pub struct PrivateEntry{
    timestamp: A<DateTime>,
    hash: A<Id>,
    item: A<KeySigned<PrivateItem>>,
}
impl From<KeySigned<PrivateItem>> for PrivateEntry {
    fn from(item: KeySigned<PrivateItem>) -> Self {
        PrivateEntry{
            timestamp: A(item.as_ref().datetime),
            hash: A(Id::hash(&item)),
            item: A(item),
        }
    }
}

pub type PrivateTable = BTreeMap<PublicKey, PrivateEntry>;

pub struct Service(Connection);
impl Service {
    pub async fn new(
        path: Option<PathBuf>,
    ) -> Result<Self, rusqlite::Error> {
        Ok(Service(Connection::open(path.unwrap_or(PathBuf::from(Self::NAME)))?))
    }
}
impl ServiceTrait for Service {
    const NAME: &str = "Storage";
    type Request = Request;
    fn catalog(&self) -> String {serde_json::to_string(&Catalog{}).unwrap()}
    async fn process(&mut self, _resolver: &mut Resolver, _secret: &Secret, request: Request) -> Response {
        let time = std::time::Instant::now();
        let read_private = matches!(request, Request::ReadPrivate(_));
        let result = match &request {
            Request::CreatePrivate(signed) | Request::CreateReadPrivate(signed) => {
                match signed.verify() {
                    Err(e) => Response::InvalidSignature(e.to_string()),
                    Ok(discover) if discover != signed.as_ref().discover =>
                        Response::InvalidRequest("Discover key mismatch between Signature and Payload".to_string()),
                    Ok(_) if (now() - signed.as_ref().datetime).num_minutes().abs() > 1 => 
                        Response::InvalidRequest("Datetime for PrivateItem is not within the minute".to_string()),
                    Ok(discover) => match request {
                        Request::CreatePrivate(signed) => Response::CreatePrivate(
                            PrivateTable::read_sub::<A<DateTime>>(
                                &self.0, &[&discover.to_string(), "timestamp"]
                            ).unwrap().map(|d| {
                                (d.0, PrivateTable::read_sub::<A<Id>>(
                                    &self.0, &[&discover.to_string(), "hash"]
                                ).unwrap().unwrap().0)
                            }).or_else(|| {
                                PrivateTable::create_sub(
                                    &self.0, &[&discover.to_string()], &PrivateEntry::from(signed)
                                ).unwrap();
                                None
                            })
                        ),
                        Request::CreateReadPrivate(signed) => Response::CreateReadPrivate(
                            PrivateTable::read_sub::<A<Id>>(
                                &self.0, &[&discover.to_string(), "hash"]
                            ).unwrap().map(|d| {
                                (d.0, PrivateTable::read_sub::<A<KeySigned<PrivateItem>>>(
                                    &self.0, &[&discover.to_string(), "item"]
                                ).unwrap().unwrap().0)
                            }).or_else(|| {
                                PrivateTable::create_sub(
                                    &self.0, &[&discover.to_string()], &PrivateEntry::from(signed)
                                ).unwrap();
                                None
                            })
                        ),
                        _ => panic!("noop")
                    },
                }
            },
            Request::ReadPrivate(signed) | Request::ReadPrivateHash(signed) => {
                match signed.verify() {
                    Ok(discover) => {
                        let timestamp = PrivateTable::read_sub::<A<DateTime>>(
                            &self.0, &[&discover.to_string(), "timestamp"]
                        ).unwrap();
                        let hash = PrivateTable::read_sub::<A<Id>>(
                            &self.0, &[&discover.to_string(), "hash"]
                        ).unwrap();
                        if read_private {
                            let item = PrivateTable::read_sub::<A<KeySigned<PrivateItem>>>(
                                &self.0, &[&discover.to_string(), "item"]
                            ).unwrap();
                            Response::ReadPrivate(timestamp.map(|_| (hash.unwrap().0, item.unwrap().0)))
                        } else {
                            Response::ReadPrivateHash(timestamp.map(|t| (t.0, hash.unwrap().0)))
                        }
                    },
                    Err(e) => Response::InvalidSignature(e.to_string())
                }
            },
          //Request::CreatePublic(signed) => {
          //    match signed.verify(resolver, None).await {
          //        Ok(signer) => {
          //            let id = Id::random();
          //            self.0.execute(
          //                "INSERT INTO public(id, signer, protocol, timestamp, payload) VALUES (?1, ?2, ?3, ?4, ?5);",
          //                params![id.to_string(), signer.to_string(), signed.as_ref().protocol.to_string(), now().timestamp(), serde_json::to_vec(&signed).unwrap()]
          //            ).unwrap();
          //            Response::CreatedPublic(id)
          //        },
          //        Err(e) => Response::InvalidSignature(e.to_string())
          //    }
          //},
          //Request::ReadPublic(filter) => {
          //    let mut first = false;
          //    let query = format!("SELECT * FROM public{}{}{}{}",
          //        filter.id.map(|i| {first = true; format!(" WHERE id='{i}'")}).unwrap_or("".to_string()),
          //        filter.author.map(|a| {let r = format!(" {}signer='{}'", if first {"AND "} else {"WHERE "}, a); first = true; r}).unwrap_or("".to_string()),
          //        filter.protocol.map(|p| {let r = format!(" {}protocol='{}'", if first {"AND "} else {"WHERE "}, p); first = true; r}).unwrap_or("".to_string()),
          //        filter.datetime.map(|(op, d)| {
          //            let r = format!(" {}timestamp{}", if first {"AND "} else {"WHERE "}, match op {
          //                Op::LS => format!("<{}", d.timestamp()),
          //                Op::LSE => format!("<={}", d.timestamp()),
          //                Op::E => format!("={}", d.timestamp()),
          //                Op::GRE => format!(">={}", d.timestamp()),
          //                Op::GR => format!(">{}", d.timestamp()),
          //            });
          //            first = true;
          //            r
          //        }).unwrap_or("".to_string())
          //    );
          //    println!("Query: {query}");
          //    let mut stmt = self.0.prepare(&query).unwrap();
          //    Response::ReadPublic(stmt.query_map([], |r| Ok((
          //        Id::from_str(&r.get::<&str, String>("id")?).unwrap(),
          //        serde_json::from_slice::<DidSigned<PublicItem>>(&r.get::<&str, Vec<u8>>("payload")?).unwrap(),
          //        DateTime::from_timestamp(r.get(3)?, 0).unwrap()
          //    ))).unwrap().collect::<Result<Vec<_>, rusqlite::Error>>().unwrap())
          //},
          //Request::UpdatePublic(signed) => match signed.verify(resolver, None).await {
          //    Ok(author) => {
          //        let (id, payload) = signed.into_inner();
          //        match payload.verify(resolver, None).await {
          //            Ok(author2) if author == author2 => match self.0.query_row(&format!("SELECT signer FROM public WHERE id='{id}'"),
          //                    [], |r| Ok(OrangeName::from_str(&r.get::<&str, String>("signer")?).unwrap())
          //            ).optional().unwrap() {
          //                Some(author3) if author2 == author3 => {
          //                    self.0.execute("DELETE FROM public WHERE id=?1;", [id.to_string()]).unwrap();
          //                    self.0.execute(
          //                        "INSERT INTO public(id, signer, protocol, timestamp, payload) VALUES (?1, ?2, ?3, ?4, ?5);",
          //                        params![id.to_string(), author3.to_string(), payload.as_ref().protocol.to_string(), now().timestamp(), serde_json::to_vec(&payload).unwrap()]
          //                    ).unwrap();
          //                    Response::Empty
          //                },
          //                Some(_) => Response::InvalidSignature("Signer dose not match current author".to_string()),
          //                None => {
          //                    self.0.execute(
          //                        "INSERT INTO public(id, signer, protocol, timestamp, payload) VALUES (?1, ?2, ?3, ?4, ?5);",
          //                        params![id.to_string(), author2.to_string(), payload.as_ref().protocol.to_string(), now().timestamp(), serde_json::to_vec(&payload).unwrap()]
          //                    ).unwrap();
          //                    Response::Empty
          //                }
          //            },
          //            Ok(_) => Response::InvalidSignature("Signers do not match".to_string()),
          //            Err(e) => Response::InvalidSignature(e.to_string())
          //        }
          //    },
          //    Err(e) => Response::InvalidSignature(e.to_string())
          //},
          //Request::DeletePublic(signed) => match signed.verify(resolver, None).await {
          //    Ok(author) => {
          //        let id = signed.into_inner();
          //        match self.0.query_row(&format!("SELECT signer FROM public WHERE id='{id}'"),
          //                [], |r| Ok(OrangeName::from_str(&r.get::<&str, String>("signer")?).unwrap())
          //        ).optional().unwrap() {
          //            Some(author2) if author == author2 => {
          //                self.0.execute("DELETE FROM public WHERE id=?1;", [id.to_string()]).unwrap();
          //                Response::Empty
          //            },
          //            Some(_) => Response::InvalidSignature("Signer dose not match current author".to_string()),
          //            None => Response::Empty
          //        }
          //    },
          //    Err(e) => Response::InvalidSignature(e.to_string())
          //},
          //Request::CreateDM(recipient, payload) => {
          //    self.0.execute(
          //        "INSERT INTO dms(recipient, payload, timestamp) VALUES (?1, ?2, ?3);",
          //        params![recipient.to_string(), payload, now().timestamp()]
          //    ).unwrap();
          //    Response::Empty
          //},
          //Request::ReadDM(signed) => {
          //    let now = now().timestamp();
          //    let time = signed.as_ref().0.timestamp();
          //    let since = signed.as_ref().1.timestamp();
          //    match signed.verify(resolver, None).await {
          //        Ok(name) => match time <= now && time >= now-10_000 {
          //            true => {
          //                let mut stmt = self.0.prepare(&format!("SELECT payload FROM dms WHERE recipient='{name}' AND timestamp >= {since}")).unwrap();
          //                Response::ReadDM(stmt.query_map([], |r| r.get(0)).unwrap().collect::<Result<Vec<_>, rusqlite::Error>>().unwrap())
          //            },
          //            false => Response::InvalidSignature("Expired".to_string())
          //        },
          //        Err(Error::Critical(e)) => panic!("{e:?}"),
          //        Err(e) => Response::InvalidSignature(e.to_string())
          //    }
          //}
        };
        println!("completed: {:?}", time.elapsed().as_millis());
        result 
    }
}









//  pub struct Service(Connection);
//  impl Service {
//      pub async fn new(
//          path: Option<PathBuf>,
//      ) -> Result<Self, rusqlite::Error> {
//          let database = Connection::open(path.unwrap_or(PathBuf::from(NAME)))?;
//          database.execute("CREATE TABLE if not exists public(
//              id TEXT NOT NULL UNIQUE,
//              signer TEXT NOT NULL,
//              protocol TEXT NOT NULL,
//              timestamp INTERGER NOT NULL,
//              payload BLOB NOT NULL
//          );", [])?;
//          database.execute("CREATE TABLE if not exists private(
//              discover TEXT NOT NULL UNIQUE,
//              timestamp INTERGER NOT NULL,
//              del TEXT,
//              payload BLOB,
//              header BLOB,
//          );", [])?;
//          database.execute("CREATE TABLE if not exists dms(
//              recipient TEXT NOT NULL,
//              payload BLOB NOT NULL,
//              timestamp INTERGER NOT NULL
//          );", [])?;
//          Ok(Service(database))
//      }
//  }

//  impl ServiceTrait for Service {
//      type Request = Request;
//      fn name(&self) -> String {NAME.to_string()}
//      fn catalog(&self) -> String {serde_json::to_string(&Catalog{}).unwrap()}
//      async fn process(&mut self, resolver: &mut Resolver, request: Request) -> Response {
//          let time = std::time::Instant::now();
//          let result = match request {
//              Request::CreatePrivate(signed) => {
//                  match signed.verify() {
//                      Ok(discover) => {
//                          if discover != signed.as_ref().discover {return Response::InvalidRequest("Discover key mismatch between Signature and Payload".to_string());}
//                          if let Some(datetime) = self.0.query_row(&format!("SELECT timestamp FROM private WHERE discover='{discover}'"),
//                              [], |r| Ok(
//                                  DateTime::from_timestamp(r.get(0)?, 0).unwrap()
//                              )
//                          ).optional().unwrap() {
//                              Response::CreatePrivate(Some(datetime))
//                          } else {
//                              self.0.execute(
//                                  "INSERT INTO private(discover, del, header, payload, timestamp) VALUES (?1, ?2, ?3, ?4, ?5);",
//                                  params![
//                                      discover.to_string(),
//                                      signed.as_ref().delete.map(|d| d.to_string()),
//                                      serde_json::to_vec(&signed.as_ref().header).unwrap(),
//                                      serde_json::to_vec(&signed).unwrap(),
//                                      now().timestamp()
//                                  ]
//                              ).unwrap();
//                              Response::CreatePrivate(None)
//                          }
//                      },
//                      Err(e) => Response::InvalidSignature(e.to_string())
//                  }
//              },
//              Request::ReadPrivateHeader(signed) => {
//                  match signed.verify() {
//                      Ok(discover) => self.0.query_row(&format!(
//                              "SELECT header, timestamp FROM private WHERE discover='{discover}'"
//                          ), [], |r| Ok(Response::ReadPrivateHeader(Some((
//                              DateTime::from_timestamp(r.get(1).unwrap(), 0).unwrap(),
//                              r.get::<usize, Vec<u8>>(0).optional()?.map(|p|
//                                  serde_json::from_slice(&p).unwrap(),
//                              ),
//                          ))))
//                      ).optional().unwrap().unwrap_or(Response::ReadPrivateHeader(None)),
//                      Err(e) => Response::InvalidSignature(e.to_string())
//                  }
//              },
//              Request::ReadPrivate(signed) => {
//                  match signed.verify() {
//                      Ok(discover) => self.0.query_row(&format!(
//                              "SELECT payload, timestamp FROM private WHERE discover='{discover}'"
//                          ), [], |r| Ok(Response::ReadPrivate(Some((
//                              DateTime::from_timestamp(r.get(1).unwrap(), 0).unwrap(),
//                              r.get::<usize, Vec<u8>>(0).optional()?.map(|p|
//                                  serde_json::from_slice(&p).unwrap()
//                              ),
//                          ))))
//                      ).optional().unwrap().unwrap_or(Response::ReadPrivate(None)),
//                      Err(e) => Response::InvalidSignature(e.to_string())
//                  }
//              },
//              Request::DeletePrivate(signed) => {
//                  match signed.verify() {
//                      Ok(delete) => {
//                          let discover = signed.as_ref();
//                          let old_delete: Option<String> = self.0.query_row(
//                              &format!("SELECT delete private WHERE discover='{discover}' AND NOT payload=NULL"), [], |r| r.get(0)
//                          ).optional().unwrap();
//                          if let Some(old_delete) = old_delete {
//                              let old_delete = serde_json::from_str(&old_delete).unwrap();
//                              if delete != old_delete {
//                                  return Response::InvalidDelete(Some(old_delete));
//                              }
//                              self.0.execute(
//                                  "INSERT INTO private(discover, payload, header)
//                                   VALUES (?1, NULL, NULL)
//                                   ON CONFLICT DO UPDATE SET
//                                   payload=excluded.payloa,d
//                                   header=excluded.header;
//                                  ", [discover.to_string()]
//                              ).unwrap();
//                          }
//                          Response::Empty
//                      },
//                      Err(e) => Response::InvalidSignature(e.to_string())
//                  }
//              },
//              Request::CreatePublic(signed) => {
//                  match signed.verify(resolver, None).await {
//                      Ok(signer) => {
//                          let id = Id::random();
//                          self.0.execute(
//                              "INSERT INTO public(id, signer, protocol, timestamp, payload) VALUES (?1, ?2, ?3, ?4, ?5);",
//                              params![id.to_string(), signer.to_string(), signed.as_ref().protocol.to_string(), now().timestamp(), serde_json::to_vec(&signed).unwrap()]
//                          ).unwrap();
//                          Response::CreatedPublic(id)
//                      },
//                      Err(e) => Response::InvalidSignature(e.to_string())
//                  }
//              },
//              Request::ReadPublic(filter) => {
//                  let mut first = false;
//                  let query = format!("SELECT * FROM public{}{}{}{}",
//                      filter.id.map(|i| {first = true; format!(" WHERE id='{i}'")}).unwrap_or("".to_string()),
//                      filter.author.map(|a| {let r = format!(" {}signer='{}'", if first {"AND "} else {"WHERE "}, a); first = true; r}).unwrap_or("".to_string()),
//                      filter.protocol.map(|p| {let r = format!(" {}protocol='{}'", if first {"AND "} else {"WHERE "}, p); first = true; r}).unwrap_or("".to_string()),
//                      filter.datetime.map(|(op, d)| {
//                          let r = format!(" {}timestamp{}", if first {"AND "} else {"WHERE "}, match op {
//                              Op::LS => format!("<{}", d.timestamp()),
//                              Op::LSE => format!("<={}", d.timestamp()),
//                              Op::E => format!("={}", d.timestamp()),
//                              Op::GRE => format!(">={}", d.timestamp()),
//                              Op::GR => format!(">{}", d.timestamp()),
//                          });
//                          first = true;
//                          r
//                      }).unwrap_or("".to_string())
//                  );
//                  println!("Query: {query}");
//                  let mut stmt = self.0.prepare(&query).unwrap();
//                  Response::ReadPublic(stmt.query_map([], |r| Ok((
//                      Id::from_str(&r.get::<&str, String>("id")?).unwrap(),
//                      serde_json::from_slice::<DidSigned<PublicItem>>(&r.get::<&str, Vec<u8>>("payload")?).unwrap(),
//                      DateTime::from_timestamp(r.get(3)?, 0).unwrap()
//                  ))).unwrap().collect::<Result<Vec<_>, rusqlite::Error>>().unwrap())
//              },
//              Request::UpdatePublic(signed) => match signed.verify(resolver, None).await {
//                  Ok(author) => {
//                      let (id, payload) = signed.into_inner();
//                      match payload.verify(resolver, None).await {
//                          Ok(author2) if author == author2 => match self.0.query_row(&format!("SELECT signer FROM public WHERE id='{id}'"),
//                                  [], |r| Ok(OrangeName::from_str(&r.get::<&str, String>("signer")?).unwrap())
//                          ).optional().unwrap() {
//                              Some(author3) if author2 == author3 => {
//                                  self.0.execute("DELETE FROM public WHERE id=?1;", [id.to_string()]).unwrap();
//                                  self.0.execute(
//                                      "INSERT INTO public(id, signer, protocol, timestamp, payload) VALUES (?1, ?2, ?3, ?4, ?5);",
//                                      params![id.to_string(), author3.to_string(), payload.as_ref().protocol.to_string(), now().timestamp(), serde_json::to_vec(&payload).unwrap()]
//                                  ).unwrap();
//                                  Response::Empty
//                              },
//                              Some(_) => Response::InvalidSignature("Signer dose not match current author".to_string()),
//                              None => {
//                                  self.0.execute(
//                                      "INSERT INTO public(id, signer, protocol, timestamp, payload) VALUES (?1, ?2, ?3, ?4, ?5);",
//                                      params![id.to_string(), author2.to_string(), payload.as_ref().protocol.to_string(), now().timestamp(), serde_json::to_vec(&payload).unwrap()]
//                                  ).unwrap();
//                                  Response::Empty
//                              }
//                          },
//                          Ok(_) => Response::InvalidSignature("Signers do not match".to_string()),
//                          Err(e) => Response::InvalidSignature(e.to_string())
//                      }
//                  },
//                  Err(e) => Response::InvalidSignature(e.to_string())
//              },
//              Request::DeletePublic(signed) => match signed.verify(resolver, None).await {
//                  Ok(author) => {
//                      let id = signed.into_inner();
//                      match self.0.query_row(&format!("SELECT signer FROM public WHERE id='{id}'"),
//                              [], |r| Ok(OrangeName::from_str(&r.get::<&str, String>("signer")?).unwrap())
//                      ).optional().unwrap() {
//                          Some(author2) if author == author2 => {
//                              self.0.execute("DELETE FROM public WHERE id=?1;", [id.to_string()]).unwrap();
//                              Response::Empty
//                          },
//                          Some(_) => Response::InvalidSignature("Signer dose not match current author".to_string()),
//                          None => Response::Empty
//                      }
//                  },
//                  Err(e) => Response::InvalidSignature(e.to_string())
//              },
//              Request::CreateDM(recipient, payload) => {
//                  self.0.execute(
//                      "INSERT INTO dms(recipient, payload, timestamp) VALUES (?1, ?2, ?3);",
//                      params![recipient.to_string(), payload, now().timestamp()]
//                  ).unwrap();
//                  Response::Empty
//              },
//              Request::ReadDM(signed) => {
//                  let now = now().timestamp();
//                  let time = signed.as_ref().0.timestamp();
//                  let since = signed.as_ref().1.timestamp();
//                  match signed.verify(resolver, None).await {
//                      Ok(name) => match time <= now && time >= now-10_000 {
//                          true => {
//                              let mut stmt = self.0.prepare(&format!("SELECT payload FROM dms WHERE recipient='{name}' AND timestamp >= {since}")).unwrap();
//                              Response::ReadDM(stmt.query_map([], |r| r.get(0)).unwrap().collect::<Result<Vec<_>, rusqlite::Error>>().unwrap())
//                          },
//                          false => Response::InvalidSignature("Expired".to_string())
//                      },
//                      Err(Error::Critical(e)) => panic!("{e:?}"),
//                      Err(e) => Response::InvalidSignature(e.to_string())
//                  }
//              }
//          };
//          println!("completed: {:?}", time.elapsed().as_millis());
//          result
//      }
//  }
