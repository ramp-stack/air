use crate::names::{now, Error, Id};
use crate::names::secp256k1::{Signed as KeySigned, PublicKey, Signature as KeySignature};

use serde::{Serialize, Deserialize};

use std::collections::{HashMap, HashSet};
use std::hash::Hash;
use std::fmt::Debug;

#[derive(Serialize, Deserialize, Debug, Clone, Hash, PartialEq, Eq)]
pub enum Request{
    Create(KeySigned<Vec<u8>>),
    Read(PublicKey),
}

#[derive(Debug)]
pub enum DBRequest {
    FileRead(PublicKey),
    FileWrite(u64, KeySigned<Vec<u8>>),
}

#[derive(Debug)]
pub enum DBResponse {
    File(Option<(u64, KeySignature, Vec<u8>)>),
}

#[derive(Serialize, Deserialize, Debug, Clone, Hash, PartialEq, Eq)]
pub enum Response {
    Created(u64),
    Read(u64, Option<(KeySignature, Vec<u8>)>),
    InvalidSignature,
}

#[derive(Debug)]
pub enum Output {
    Read,
    Empty(PublicKey),
    Created(KeySigned<Vec<u8>>),
    InvalidSignature
}

#[derive(Default)]
pub struct Storage;
impl Storage {
    async fn request(request: Request) -> Result<DBRequest, Error> {
        Ok(match request {
            Request::Create(signed) => {
                signed.verify()?;
                //let hash = Id::hash(&signed.payload);
                let timestamp = now();
                //let signature = secret.sign(Id::hash(&(signed.key, timestamp, hash)));
                DBRequest::FileWrite(timestamp, signed)
            },
            Request::Read(key) => DBRequest::FileRead(key),
        })
    }

    async fn response(request: DBRequest, response: DBResponse) -> (Output, Response) {match (request, response) {
        (DBRequest::FileWrite(_, _) | DBRequest::FileRead(_), DBResponse::File(Some((timestamp, key_sig, payload)))) =>
            (Output::Read, Response::Read(timestamp, Some((key_sig, payload)))),
        (DBRequest::FileWrite(timestamp, signed), DBResponse::File(None)) => 
            (Output::Created(signed), Response::Created(timestamp)),
        (DBRequest::FileRead(key), DBResponse::File(None)) => {
            let time = now();
            //let hash = Id::hash(&(key, time, Id::MIN));
            (Output::Empty(key), Response::Read(time, None))
        },
    }}

    pub async fn run(request: Request, mut handle: impl FnMut(&DBRequest) -> DBResponse) -> (Output, Response) {
        match Storage::request(request).await {
            Ok(req) => {
                let res = handle(&req);
                Self::response(req, res).await
            },
            Err(_) => (Output::InvalidSignature, Response::InvalidSignature)
        }
    }
}

#[derive(Default)]
pub struct Subscriptions {
    files: HashMap<PublicKey, HashSet<(u64, u64, Id)>>,
}
impl Subscriptions {
    pub fn process(&mut self, id: (u64, u64, Id), output: Output, response: Response) -> HashMap<(u64, u64, Id), Response> {match (output, response) {
        (Output::Created(signed), Response::Created(time)) => {
            println!("files: {:?}", self.files);
            let mut map = self.files.remove(&signed.key).map(|ids| ids.into_iter().filter(|i| i.0 != id.0).map(|i|
                (i, Response::Read(time, Some((signed.signature, signed.payload.clone()))))
            ).collect::<HashMap<_, _>>()).unwrap_or_default();
            map.insert(id, Response::Created(time));
            map
        },
        (Output::Read, response) => HashMap::from([(id, response)]),
        (Output::Empty(key), response) => {
            self.files.entry(key).or_default().insert(id);
            HashMap::from([(id, response)])
        },
        (Output::InvalidSignature, Response::InvalidSignature) => HashMap::from([(id, Response::InvalidSignature)]),
        (o, r) => panic!("Unknown Output: {o:?}, {r:?}")
    }}

    pub fn close_socket(&mut self, socket: u64) {
        self.files.retain(|_, s| {s.retain(|s| s.0 != socket); !s.is_empty()});
    }
}
