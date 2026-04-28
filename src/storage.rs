use std::hash::Hash;
use std::fmt::Debug;
use std::collections::BTreeMap;

use crate::names::{now, Signed, secp256k1::{Signed as KeySigned, PublicKey}, Id, Secret, Resolver, Name};

use serde::{Serialize, Deserialize};
use rusqlite::{Connection, params, OptionalExtension, Error};

#[derive(Serialize, Deserialize, Clone, Debug, Hash, PartialEq, Eq)]
pub struct Metadata {
    pub timestamp: u64,
    pub hash: Id,
    pub len: usize
}

impl Metadata {
    pub fn new(payload: &[u8]) -> Metadata {
        Metadata{
            timestamp: now(),
            hash: Id::hash(payload),
            len: payload.len()
        }
    }
}

pub type Receipt = Signed<Metadata>;

pub type Time = (Compare, u64);

#[derive(Serialize, Deserialize, Debug, Clone, Hash, PartialEq, Eq, Copy)]
pub enum Compare {Greater, GreaterOrEqual, Equal, LesserOrEqual, Lesser}
impl std::fmt::Display for Compare {fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {write!(f, "{}", match self {
    Self::Greater => "<".to_string(),
    Self::GreaterOrEqual => ">=".to_string(),
    Self::Equal => "=".to_string(),
    Self::LesserOrEqual => "<=".to_string(),
    Self::Lesser => ">".to_string(),
})}}

#[derive(Serialize, Deserialize, Debug, Clone, Hash, PartialEq, Eq)]
pub enum Request{
    Create(KeySigned<Vec<u8>>, bool),
    Read(PublicKey, bool),

    Send(Name, Vec<u8>),
    Receive(Signed<Time>),

  //Publish(Signed<Missive>),
  //Query(Option<Name>, Option<Id>, Option<Id>, Option<Time>, u32)
}

#[derive(Serialize, Deserialize, Debug, Clone, Hash, PartialEq, Eq)]
pub enum Response {
    Receipt(Receipt),

    Private(Receipt, KeySigned<Vec<u8>>),
    Inbox(Vec<(Receipt, Vec<u8>)>),
    //Query(BTreeMap<(Name, Id, Id), (Signed<Metadata>, Signed<Missive>)>),

    InvalidRequest(String),
    InvalidSignature(String),
}

pub struct Service(pub bool);
impl Service {
    pub async fn process(&mut self, connection: &mut Connection, secret: &Secret, request: Request) -> Response {
        if self.0 {
            self.0 = false;
            connection.execute("CREATE TABLE if not exists private(
                discover TEXT NOT NULL UNIQUE,
                metadata BLOB NOT NULL,
                payload BLOB NOT NULL
            );", []).unwrap();
            connection.execute("CREATE TABLE if not exists public(
                author TEXT NOT NULL,
                contract_id TEXT NOT NULL,
                instance_id TEXT NOT NULL,
                timestamp INT NOT NULL,
                metadata BLOB NOT NULL,
                payload BLOB NOT NULL
            );", []).unwrap();
            connection.execute("CREATE TABLE if not exists inbox(
                recipient TEXT NOT NULL,
                timestamp INT NOT NULL,
                metadata BLOB NOT NULL,
                payload BLOB NOT NULL
            );", []).unwrap();

        }
        println!("request: {:?}", request);
        let response = match request {
            Request::Create(payload, inc) => {
                let metadata = Signed::new(secret, Metadata::new(payload.as_ref())).unwrap();
                match payload.verify(None) {
                    Ok(discover) => match inc {
                        true => {
                            let result = connection.query_row(
                                "INSERT INTO private(discover, metadata, payload) VALUES (?1, ?2, ?3) ON CONFLICT DO UPDATE SET discover=discover RETURNING metadata, payload;",
                                params![
                                    discover.to_string(),
                                    serde_json::to_vec(&metadata).unwrap(),
                                    serde_json::to_vec(&payload).unwrap(),
                                ],
                                |row| Ok((
                                    serde_json::from_slice::<Receipt>(&row.get::<_, Vec<u8>>(0)?).unwrap(),
                                    serde_json::from_slice::<KeySigned<Vec<u8>>>(&row.get::<_, Vec<u8>>(1)?).unwrap(),
                                ))
                            ).unwrap();
                            if result.0 == metadata {Response::Receipt(metadata)} else {Response::Private(result.0, result.1)}
                        },
                        false => {
                            let result = connection.query_row(
                                "INSERT INTO private(discover, metadata, payload) VALUES (?1, ?2, ?3) ON CONFLICT DO UPDATE SET discover=discover RETURNING metadata;",
                                params![
                                    discover.to_string(),
                                    serde_json::to_vec(&metadata).unwrap(),
                                    serde_json::to_vec(&payload).unwrap(),
                                ],
                                |row| Ok(serde_json::from_slice::<Receipt>(&row.get::<_, Vec<u8>>(0)?).unwrap())
                            ).unwrap();
                            if result == metadata {Response::Receipt(metadata)} else {Response::Receipt(result)}
                        }
                    },
                    Err(e) => Response::InvalidSignature(e.to_string())
                }
            },
            Request::Read(discover, inc) => {
                let now = now();
                match inc {
                    true => connection.query_row(
                        &format!("SELECT metadata, payload FROM private WHERE discover='{discover}'"),
                        [], |r| Ok(Response::Private(
                            serde_json::from_slice(&r.get::<_, Vec<u8>>(0)?).unwrap(),
                            serde_json::from_slice(&r.get::<_, Vec<u8>>(1)?).unwrap(),
                        ))
                    ).optional().unwrap(),
                    false => connection.query_row(
                        &format!("SELECT metadata FROM private WHERE discover='{discover}'"),
                        [], |r| Ok(Response::Receipt(serde_json::from_slice(&r.get::<_, Vec<u8>>(0)?).unwrap()))
                    ).optional().unwrap()
                }.unwrap_or_else(|| Response::Receipt(Signed::new(secret, Metadata{
                    timestamp: now,
                    hash: Id::MIN,
                    len: 0
                }).unwrap()))
            },
          //Request::Publish(missive) => {
          //    match missive.verify(&mut Resolver, None, None).await {
          //        Ok(author) => {
          //            let payload = serde_json::to_vec(&missive).unwrap();
          //            let metadata = Signed::new(secret, Metadata::new(&payload)).unwrap();
          //            connection.execute(
          //                "INSERT INTO public(author, contract_id, instance_id, timestamp, metadata, payload) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
          //                params![
          //                    author.to_string(),
          //                    missive.as_ref().contract_id().to_string(),
          //                    Missive::instance_id(&missive).to_string(),
          //                    metadata.as_ref().timestamp as isize,
          //                    serde_json::to_vec(&metadata).unwrap(),
          //                    payload,
          //                ],
          //            ).unwrap();
          //            Response::Receipt(metadata)
          //        },
          //        Err(e) => Response::InvalidSignature(e.to_string())
          //    }
          //},
          //Request::Query(author, contract_id, instance_id, time, limit) => {
          //    todo!()
          //},
            Request::Send(recipient, payload) => {
                let metadata = Signed::new(secret, Metadata::new(payload.as_ref())).unwrap();
                connection.execute(
                    "INSERT INTO inbox(recipient, timestamp, metadata, payload) VALUES (?1, ?2, ?3, ?4)",
                    params![
                        recipient.to_string(),
                        metadata.as_ref().timestamp as isize,
                        serde_json::to_vec(&metadata).unwrap(),
                        payload,
                    ],
                ).unwrap();
                Response::Receipt(metadata)
            },
            Request::Receive(signed) => match signed.verify(&mut Resolver, None, None).await {
                Ok(recipient) => {
                    let (ordering, timestamp) = signed.into_inner();
                    Response::Inbox(connection.prepare(&format!("SELECT metadata, payload FROM inbox WHERE recipient='{recipient}' AND timestamp{ordering}'{timestamp}'")).unwrap().query_map(
                        [], |r| Ok((
                            serde_json::from_slice(&r.get::<_, Vec<u8>>(0)?).unwrap(),
                            r.get::<_, Vec<u8>>(1)?,
                        ))
                    ).unwrap().collect::<Result<Vec<_>, Error>>().unwrap())
                },
                Err(e) => Response::InvalidSignature(e.to_string())
            },
        };
        println!("response: {:?}", response);
        response
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::Purser;
    use crate::names::{Name, secp256k1::{SecretKey}, Resolver};

    async fn run(name: &Name, request: Request) -> Response {
        Purser::send(&mut Resolver, name, request).await.unwrap()
    }

    fn metadata(response: Response) -> Option<(Id, usize)> {
        match response {
            Response::Receipt(m) => Some((m.as_ref().hash, m.as_ref().len)),
            _ => None,
        }
    }

    fn private(response: Response) -> Option<Vec<u8>> {
        match response {
            Response::Private(_, p) => Some(p.into_inner()),
            _ => None,
        }
    }

    fn inbox(response: Response) -> Option<Vec<Vec<u8>>> {
        match response {
            Response::Inbox(i) => Some(i.into_iter().map(|(_, p)| p).collect()),
            _ => None,
        }
    }

  //fn inbox(response: Response) -> Option<Vec<Vec<u8>>> {
  //    match response {
  //        Response::Inbox(i) => Some(i.into_iter().map(|(_, p)| p).collect()),
  //        _ => None,
  //    }
  //}

    

    #[tokio::test]
    async fn test_private() {
        let key = SecretKey::new();
        let item = KeySigned::new(&key, b"hello".to_vec());
        let other = KeySigned::new(&key, b"other".to_vec());
        let hash = Metadata::new(item.as_ref()).hash;
        assert_eq!(metadata(run(&Name::orange_me(), Request::Read(key.public_key(), false)).await), Some((Id::MIN, 0)));
        assert_eq!(metadata(run(&Name::orange_me(), Request::Create(item.clone(), false)).await), Some((hash, 5)));
        assert_eq!(metadata(run(&Name::orange_me(), Request::Create(other.clone(), false)).await), Some((hash, 5)));
        assert_eq!(private(run(&Name::orange_me(), Request::Create(other, true)).await), Some(item.clone().into_inner()));
        assert_eq!(private(run(&Name::orange_me(), Request::Read(key.public_key(), true)).await), Some(item.clone().into_inner()));
        assert_eq!(metadata(run(&Name::orange_me(), Request::Read(key.public_key(), false)).await), Some((hash, 5)));
        assert_eq!(metadata(run(&Name::orange_me(), Request::Create(KeySigned::new(&key, b"goodbye".to_vec()), false)).await), Some((hash, 5)));
    }

  //#[tokio::test]
  //async fn test_public() {
  //    let secret = Secret::new();
  //    let name = secret.name();
  //    let missive = Missive(Id::hash("Contract"), b"payload".to_vec(), SecretKey::new());
  //    let signed = Signed::new(&secret, missive).unwrap();
  //    let iid = Missive::instance_id(&signed);
  //    let md = Metadata::new(&serde_json::to_vec(&signed).unwrap());
  //    assert_eq!(metadata(run(&Name::orange_me(), Request::Publish(signed)).await), Some((md.hash, md.len)));
  //}

    #[tokio::test]
    async fn test_inbox() {
        let secret = Secret::new();
        let name = secret.name();
        let item = b"hello bob".to_vec();
        let hash = Id::hash(&item);
        let time = (Compare::GreaterOrEqual, 0);
        assert_eq!(inbox(run(&Name::orange_me(), Request::Receive(Signed::new(&secret, time).unwrap())).await), Some(vec![]));
        assert_eq!(metadata(run(&Name::orange_me(), Request::Send(name, item.clone())).await), Some((hash, 9)));
        assert_eq!(inbox(run(&Name::orange_me(), Request::Receive(Signed::new(&secret, time).unwrap())).await), Some(vec![item.clone()]));
        assert_eq!(metadata(run(&Name::orange_me(), Request::Send(name, item.clone())).await), Some((hash, 9)));
        assert_eq!(inbox(run(&Name::orange_me(), Request::Receive(Signed::new(&secret, time).unwrap())).await), Some(vec![item.clone(), item]));
    }
}
