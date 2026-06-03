use std::collections::HashMap;
use std::hash::Hash;
use std::fmt::Debug;

use crate::names::{now, Name, Signature, Id, Secret, Signed, Resolver};
use crate::names::secp256k1::{Signature as KeySignature, Signed as KeySigned, PublicKey};

use serde::{Serialize, Deserialize};
use rusqlite::{Connection, params, OptionalExtension};

use crossfire::{MAsyncTx, AsyncTx, AsyncRx, mpsc, spsc};
use tokio::spawn;

pub type Time = (Compare, u64);

#[derive(Serialize, Deserialize, Debug, Clone, Hash, PartialEq, Eq, Copy)]
pub enum Compare {Greater, GreaterOrEqual, Equal, LesserOrEqual, Lesser}
impl std::fmt::Display for Compare {fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {write!(f, "{}", match self {
    Self::Greater => ">".to_string(),
    Self::GreaterOrEqual => ">=".to_string(),
    Self::Equal => "=".to_string(),
    Self::LesserOrEqual => "<=".to_string(),
    Self::Lesser => "<".to_string(),
})}}

#[derive(Serialize, Deserialize, Debug, Clone, Hash, PartialEq, Eq)]
pub enum Request{
    Create(KeySigned<Vec<u8>>),
    Read(PublicKey, bool),//Subscribe

    Send(Name, Vec<u8>),
    Receive(Signed<Time>),
}

#[derive(Serialize, Deserialize, Debug, Clone, Hash, PartialEq, Eq)]
pub enum Response {
    Create(Signature, u64),
    Read(Signature, u64, Option<(KeySignature, Vec<u8>)>),
    
    Inbox(Vec<(Signature, u64, Vec<u8>)>),

    InvalidRequest(String),
    InvalidSignature(String),
}

type Responder = AsyncTx<spsc::One<Response>>;

#[derive(Clone)]
pub struct Storage(MAsyncTx<mpsc::List<(Request, Responder)>>);
impl Storage {
    pub fn start(secret: &Secret) -> Self {
        let (tx, rx) = mpsc::build(mpsc::List::new());
        let resolver = Resolver::start();
        spawn(Self::run(resolver, secret.clone(), rx));
        Storage(tx)
    }

    pub async fn request(&mut self, request: Request) -> AsyncRx<spsc::One<Response>> {
        let (stx, srx) = spsc::build(spsc::One::new());
        self.0.send((request, stx)).await.unwrap();
        srx
    }

    async fn run(mut resolver: Resolver, secret: Secret, rx: AsyncRx<mpsc::List<(Request, Responder)>>) {
        let mut subscriptions = HashMap::<PublicKey, Vec<Responder>>::new();
        let mut subscriptions_inbox = HashMap::<Name, Vec<Responder>>::new();
        let connection = Connection::open("STORAGE.db").unwrap();
        connection.execute("CREATE TABLE if not exists private(
            key TEXT NOT NULL UNIQUE,
            key_signature BLOB NOT NULL,
            signature BLOB NOT NULL,
            timestamp BLOB NOT NULL,
            payload BLOB NOT NULL
        );", []).unwrap();

        connection.execute("CREATE TABLE if not exists inbox(
            recipient TEXT NOT NULL,
            timestamp INT NOT NULL,
            signature BLOB NOT NULL,
            payload BLOB NOT NULL
        );", []).unwrap();

        while let Ok((request, responder)) = rx.recv().await {
            println!("request: {:?}", request);
            match request {
                Request::Create(signed) => {
                    let hash = Id::hash(&signed.payload);
                    let timestamp = now();
                    let signature = secret.sign(Id::hash(&(signed.key, timestamp, hash)));
                    match signed.verify() {
                        Ok(()) => {
                            let result = connection.query_row(
                                "INSERT INTO private(key, signature, timestamp, key_signature, payload)
                                 VALUES (?1, ?2, ?3, ?4, ?5) ON CONFLICT DO UPDATE SET key=?1
                                 RETURNING signature, key_signature, timestamp, payload;",
                                params![
                                    postcard::to_allocvec(&signed.key).unwrap(),
                                    postcard::to_allocvec(&signature).unwrap(),
                                    postcard::to_allocvec(&timestamp).unwrap(),
                                    postcard::to_allocvec(&signed.signature).unwrap(),
                                    signed.payload
                                ],
                                |row| Ok((
                                    postcard::from_bytes::<Signature>(&row.get::<_, Vec<u8>>("signature")?).unwrap(),
                                    postcard::from_bytes::<u64>(&row.get::<_, Vec<u8>>("timestamp")?).unwrap(),
                                    postcard::from_bytes::<KeySignature>(&row.get::<_, Vec<u8>>("key_signature")?).unwrap(),
                                    row.get::<_, Vec<u8>>("payload")?
                                ))
                            ).unwrap();
                            if signature == result.0 {
                                if let Some(responders) = subscriptions.remove(&signed.key) {
                                    let response = Response::Read(result.0.clone(), result.1, Some((result.2, result.3)));
                                    for responder in responders {
                                        responder.send(response.clone()).await.unwrap();
                                    }
                                }
                                responder.send(Response::Create(result.0, result.1)).await.unwrap()
                            } else {
                                responder.send(Response::Read(result.0, result.1, Some((result.2, result.3)))).await.unwrap()
                            }
                        },
                        Err(e) => responder.send(Response::InvalidSignature(e.to_string())).await.unwrap(),
                    }
                },
                Request::Read(key, subscribe) => {
                    if let Some(read) = connection.query_row(
                        "SELECT signature, timestamp, key_signature, payload FROM private WHERE key=?1",
                        [postcard::to_allocvec(&key).unwrap()], |row| Ok(Response::Read(
                            postcard::from_bytes::<Signature>(&row.get::<_, Vec<u8>>("signature")?).unwrap(),
                            postcard::from_bytes::<u64>(&row.get::<_, Vec<u8>>("timestamp")?).unwrap(),
                            Some((
                                postcard::from_bytes::<KeySignature>(&row.get::<_, Vec<u8>>("key_signature")?).unwrap(),
                                row.get::<_, Vec<u8>>("payload")?
                            ))
                        ))
                    ).optional().unwrap() {
                        responder.send(read).await.unwrap()
                    } else {
                        if subscribe {
                            subscriptions.entry(key).or_default().push(responder);
                        } else {
                            let timestamp = now();
                            let id = Id::hash(&timestamp);
                            responder.send(Response::Read(secret.sign(id), timestamp, None)).await.unwrap()
                        }
                    }
                },
                Request::Send(recipient, payload) => {
                    let timestamp = now();
                    let signature = secret.sign(Id::hash(&(recipient, timestamp, &payload)));
                    connection.execute(
                        "INSERT INTO inbox(recipient, timestamp, signature, payload) VALUES (?1, ?2, ?3, ?4)",
                        params![
                            recipient.to_string(),
                            timestamp as isize,
                            serde_json::to_vec(&signature).unwrap(),
                            payload,
                        ],
                    ).unwrap();
                    responder.send(Response::Create(signature.clone(), timestamp)).await.unwrap();
                    if let Some(responders) = subscriptions_inbox.remove(&recipient) {
                        let response = Response::Inbox(vec![(signature, timestamp, payload)]);
                        for responder in responders {
                            responder.send(response.clone()).await.unwrap();
                        }
                    }
                },
                Request::Receive(signed) => {
                    let identity = resolver.resolve(signed.signer, None).await;
                    match signed.verify(&identity, &[]) {
                        Ok(()) => {
                            let recipient = signed.signer;
                            let (ordering, timestamp) = signed.payload;
                            let query = format!("SELECT signature, timestamp, payload FROM inbox WHERE recipient='{recipient}' AND timestamp{ordering}'{timestamp}'");
                            let results = connection.prepare(&query).unwrap().query_map(
                                [], |r| Ok((
                                    serde_json::from_slice::<Signature>(&r.get::<_, Vec<u8>>(0)?).unwrap(),
                                    r.get::<_, isize>(1)? as u64,
                                    r.get::<_, Vec<u8>>(2)?,
                                ))
                            ).unwrap().collect::<Result<Vec<_>, rusqlite::Error>>().unwrap();
                            if results.is_empty() {
                                subscriptions_inbox.entry(signed.signer).or_default().push(responder);
                            } else {
                                responder.send(Response::Inbox(results)).await.unwrap();
                            }
                        },
                        Err(e) => responder.send(Response::InvalidSignature(e.to_string())).await.unwrap()
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::names::{Resolver, secp256k1::SecretKey};

    #[tokio::test]
    async fn create() {
        let server = Secret::new();
        let server_name = server.name();
        let mut resolver = Resolver::start();
        let identity = resolver.resolve(server_name, None).await;
        let mut storage = Storage::start(&server);

        let file_key = SecretKey::new();
        let content = b"my file contents".to_vec();

        if let Response::Create(signature, timestamp) = storage.request(Request::Create(KeySigned::new(&file_key, content.clone()))).await.recv().await.unwrap() {
            signature.verify(&identity, &[], Id::hash(&(file_key.public_key(), timestamp, Id::hash(&content)))).unwrap();
        } else {panic!("Unexpected Response");}
    }

    #[tokio::test]
    async fn inbox() {
        let server = Secret::new();
        let server_name = server.name();
        let mut resolver = Resolver::start();
        let identity = resolver.resolve(server_name, None).await;
        let mut storage = Storage::start(&server);

        let bob = Secret::new();
        let bob_name = bob.name();

        let content = b"my file contents".to_vec();

        let timestamp = if let Response::Create(signature, timestamp) = storage.request(Request::Send(bob_name, content.clone())).await.recv().await.unwrap() {
            signature.verify(&identity, &[], Id::hash(&(bob_name, timestamp, &content))).unwrap();
            timestamp
        } else {panic!("Unexpected Response");};

        let request = storage.request(Request::Receive(Signed::new(&bob, (Compare::Greater, 0)))).await;
        if let Response::Inbox(received) = request.recv().await.unwrap() {
            for (signature, _, content) in received {
                signature.verify(&identity, &[], Id::hash(&(bob_name, timestamp, &content))).unwrap();
            }
        } else {panic!("Unexpected Response");}
    }
}
