use std::hash::Hash;
use std::fmt::Debug;

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

#[derive(Serialize, Deserialize, Debug, Clone, Hash, PartialEq, Eq)]
pub enum Request{
    Create(KeySigned<Vec<u8>>),
    Read(PublicKey, bool),

    Send(Name, Vec<u8>),
    Receive(Signed<u64>)
}

#[derive(Serialize, Deserialize, Debug, Clone, Hash, PartialEq, Eq)]
pub enum Response {
    Private(Receipt, KeySigned<Vec<u8>>),
    
    Inbox(Vec<(Receipt, Vec<u8>)>),

    Receipt(Receipt),

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
            connection.execute("CREATE TABLE if not exists inbox(
                recipient TEXT NOT NULL,
                timestamp INT NOT NULL,
                metadata BLOB NOT NULL,
                payload BLOB NOT NULL
            );", []).unwrap();

        }
        match request {
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
                    let timestamp = signed.into_inner();
                    Response::Inbox(connection.prepare(&format!("SELECT metadata, payload FROM inbox WHERE recipient='{recipient}' AND timestamp>='{timestamp}'")).unwrap().query_map(
                        [], |r| Ok((
                            serde_json::from_slice(&r.get::<_, Vec<u8>>(0)?).unwrap(),
                            r.get::<_, Vec<u8>>(1)?,
                        ))
                    ).unwrap().collect::<Result<Vec<_>, Error>>().unwrap())
                },
                Err(e) => Response::InvalidSignature(e.to_string())
            },
            Request::Create(payload) => {
                let metadata = Signed::new(secret, Metadata::new(payload.as_ref())).unwrap();
                match payload.verify(None) {
                    Ok(discover) => {
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
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::Purser;
    use crate::names::{Name, secp256k1::{SecretKey}, Resolver};
    use crate::chandler::Request as ChandlerRequest;

    async fn run(name: &Name, request: Request) -> Response {
        Purser.send(&mut Resolver, name, ChandlerRequest::Service(request)).await.unwrap().storage().unwrap()
    }

    fn metadata(response: Response) -> Option<(Id, usize)> {
        match response {
            Response::Receipt(m) => Some((m.as_ref().hash, m.as_ref().len)),
            _ => None,
        }
    }

    fn inbox(response: Response) -> Option<Vec<Vec<u8>>> {
        match response {
            Response::Inbox(i) => Some(i.into_iter().map(|(_, p)| p).collect()),
            _ => None,
        }
    }

    fn private(response: Response) -> Option<Vec<u8>> {
        match response {
            Response::Private(_, p) => Some(p.into_inner()),
            _ => None,
        }
    }

    #[tokio::test]
    async fn test_private() {
        let key = SecretKey::new();
        let item = KeySigned::new(&key, b"hello".to_vec());
        let hash = Metadata::new(item.as_ref()).hash;
        assert_eq!(metadata(run(&Name::orange_me(), Request::Read(key.public_key(), false)).await), Some((Id::MIN, 0)));
        assert_eq!(metadata(run(&Name::orange_me(), Request::Create(item.clone())).await), Some((hash, 5)));
        assert_eq!(private(run(&Name::orange_me(), Request::Read(key.public_key(), true)).await), Some(item.clone().into_inner()));
        assert_eq!(metadata(run(&Name::orange_me(), Request::Read(key.public_key(), false)).await), Some((hash, 5)));
        assert_eq!(metadata(run(&Name::orange_me(), Request::Create(KeySigned::new(&key, b"goodbye".to_vec()))).await), Some((hash, 5)));
    }

    #[tokio::test]
    async fn test_inbox() {
        let secret = Secret::new();
        let name = secret.name();
        let item = b"hello bob".to_vec();
        let hash = Id::hash(&item);
        assert_eq!(inbox(run(&Name::orange_me(), Request::Receive(Signed::new(&secret, 0).unwrap())).await), Some(vec![]));
        assert_eq!(metadata(run(&Name::orange_me(), Request::Send(name, item.clone())).await), Some((hash, 9)));
        assert_eq!(inbox(run(&Name::orange_me(), Request::Receive(Signed::new(&secret, 0).unwrap())).await), Some(vec![item.clone()]));
        assert_eq!(metadata(run(&Name::orange_me(), Request::Send(name, item.clone())).await), Some((hash, 9)));
        assert_eq!(inbox(run(&Name::orange_me(), Request::Receive(Signed::new(&secret, 0).unwrap())).await), Some(vec![item.clone(), item]));
    }
}
