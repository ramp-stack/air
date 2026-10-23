use serde::{Serialize, Deserialize};
use std::collections::{HashMap, HashSet};
use std::hash::Hash;
use std::fmt::Debug;
use crate::names::{Id, Signed, Secret};
use crate::names::secp256k1::{Signed as KeySigned, PublicKey, Signature as KeySignature};

pub type DBResponse = Option<(u64, KeySignature, Vec<u8>)>;

#[derive(Serialize, Deserialize, Debug, Clone, Hash, PartialEq, Eq)]
pub enum Request { Create(KeySigned<Vec<u8>>), Read(PublicKey), }

#[derive(Debug, Clone)]
pub enum DBRequest { Read(PublicKey), Write(u64, KeySigned<Vec<u8>>), }

#[derive(Serialize, Deserialize, Debug, Clone, Hash, PartialEq, Eq)]
pub enum Response { Created(u64), Read(u64, Option<(KeySignature, Vec<u8>)>), InvalidSignature, }

pub struct Storage {
    secret: Secret,
    subscriptions: HashMap<PublicKey, HashSet<(u64, u64, Id)>>,
    pending: Option<(u64, u64, Id, DBRequest)>,
}
impl Storage {
    pub fn new(secret: Secret) -> Self {
        Storage { secret, subscriptions: HashMap::new(), pending: None }
    }

    #[allow(clippy::result_large_err)]
    pub fn request(&mut self, socket: u64, index: u64, request: Request) -> Result<DBRequest, Signed<(Id, Response)>> {
        let hash = Id::hash(&request);
        let db_request = match request {
            Request::Create(signed) => signed
                .verify()
                .map(|_| {
                    DBRequest::Write(
                        chrono::Utc::now().timestamp_nanos_opt().unwrap() as u64,
                        signed,
                    )
                })
                .map_err(|_| self.sign(hash, Response::InvalidSignature))?,
            Request::Read(key) => DBRequest::Read(key),
        };
        self.pending = Some((socket, index, hash, db_request.clone()));
        Ok(db_request)
    }

    pub fn response(&mut self, response: DBResponse) -> HashMap<(u64, u64), Signed<(Id, Response)>> {
        let (socket, index, hash, db_request) =
            self.pending.take().expect("Must call request before response");
        let mut results = HashMap::new();
        let response = match (db_request, response) {
            (DBRequest::Write(_, _) | DBRequest::Read(_), Some((timestamp, key_sig, payload))) => {
                Response::Read(timestamp, Some((key_sig, payload)))
            }
            (DBRequest::Write(timestamp, signed), None) => {
                if let Some(subscriptions) = self.subscriptions.remove(&signed.key) {
                    subscriptions.into_iter().filter(|id| id.0 != socket).for_each(|(s, i, h)| {
                        results.insert(
                            (s, i),
                            self.sign(
                                h,
                                Response::Read(
                                    timestamp,
                                    Some((signed.signature, signed.payload.clone())),
                                ),
                            ),
                        );
                    })
                }
                Response::Created(timestamp)
            }
            (DBRequest::Read(key), None) => {
                self.subscriptions.entry(key).or_default().insert((socket, index, hash));
                Response::Read(chrono::Utc::now().timestamp_nanos_opt().unwrap() as u64, None)
            }
        };
        results.insert((socket, index), self.sign(hash, response));
        results
    }

    pub fn handle(
        &mut self, socket: u64, index: u64, request: Request,
        mut db_handle: impl FnMut(DBRequest) -> DBResponse,
    ) -> HashMap<(u64, u64), Signed<(Id, Response)>> {
        match self.request(socket, index, request) {
            Ok(req) => { let res = db_handle(req); self.response(res) }
            Err(response) => HashMap::from([((socket, index), response)]),
        }
    }

    fn sign(&self, request: Id, response: Response) -> Signed<(Id, Response)> {
        Signed::new(&self.secret, (request, response))
    }
}

#[cfg(test)]
pub mod test {
    use crate::names::Secret;
    use crate::names::secp256k1::{Signature as KeySignature, PublicKey};
    use super::{DBRequest, Request, Response};
    use std::collections::HashMap;

    pub struct Storage(super::Storage, HashMap<PublicKey, (u64, KeySignature, Vec<u8>)>);
    impl Storage {
        pub fn new() -> Self { Self(super::Storage::new(Secret::new()), HashMap::new()) }
        pub fn request(&mut self, socket: u64, index: u64, request: Request) -> HashMap<(u64, u64), Response> {
            self.0
                .handle(socket, index, request, |req| match req {
                    DBRequest::Read(key) => self.1.get(&key).cloned(),
                    DBRequest::Write(time, signed) => match self.1.get(&signed.key) {
                        Some(p) => Some(p.clone()),
                        None => {
                            self.1.insert(
                                signed.key,
                                (time, signed.signature, signed.payload.clone()),
                            );
                            None
                        }
                    },
                })
                .into_iter()
                .map(|(i, r)| (i, r.payload.1))
                .collect()
        }
    }
}
