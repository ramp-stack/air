use crate::names::{secp256k1::{Signed as KeySigned, SecretKey, Encrypted as KeyEncrypted}, Encrypted, Signature, Secret, Signed, Name, Id, now};

pub type Time = (Compare, u64);

#[derive(Serialize, Deserialize, Debug, Clone, Hash, PartialEq, Eq, Copy)]
pub enum Compare {Greater, GreaterOrEqual, Equal, LesserOrEqual, Lesser}

#[derive(Serialize, Deserialize, Debug, Clone, Hash, PartialEq, Eq)]
pub enum Request{
    Send(Name, Vec<u8>),
    Create(KeySigned<Vec<u8>>),

    Read(PublicKey, bool),
    Receive(Signed<Time>, bool),
}

#[derive(Serialize, Deserialize, Debug, Clone, Hash, PartialEq, Eq)]
pub enum Response {
    Created(Signature, u64),
    Read(Signature, u64, Option<(KeySignature, Vec<u8>)>),
    Inbox(Vec<(Signature, u64, Vec<u8>)>),

    InvalidRequest(String),
    InvalidSignature(String),
}

pub enum DBRequest {
    FileRead(SecretKey),
    FileWrite(SecretKey, Signature, u64, KeySignature, Vec<u8>),
    InboxRead(Name, Time),
    InboxWrite(Name, u64, Signature, Vec<u8>)
}

pub enum DBResponse {
    File(Option<(Signature, u64, KeySignature, Vec<u8>)>),
    InboxRead(Vec<(Signature, u64, Vec<u8>)>),
    InboxWrite
}

pub struct Storage(Box<dyn FnMut(DBRequest) -> DBResponse>);
impl Storage {
    pub fn new(database: impl FnMut(DBRequest) -> DBResponse) -> Self {
        Storage(Box::new(database))
    }

    fn database(&mut self, request: DBRequest) -> DBResponse {(self.0)(request)}

    async fn process(&mut self, resolver: &mut Resolver, secret: &Secret, request: Request) -> Response {
        match request {
            Request::Create(signed) => {
                let hash = Id::hash(&signed.payload);
                let timestamp = now();
                let signature = secret.sign(Id::hash(&(signed.key, timestamp, hash)));
                match signed.verify() {
                    Ok(()) => match self.database(DBRequest::FileWrite(signed.key, signature, timestamp, signed.signature, signed.payload)) {
                        DBResponse::File(Some((signature, timestamp, key_sig, payload))) => Response::Read(signed.key, signature, timestamp, Some((key_sig, payload))),
                        DBResponse::File(None) => Response::Created(signature, timestamp),
                        _ => panic!("Bad DBResponse")
                    },
                    Err(e) => Response::InvalidSignature(e.to_string())
                }
            },
            Request::Read(key, subscribe) => match self.database(DBRequest::FileRead(key)) {
                    DBResponse::File(Some((signature, timestamp, key_sig, payload))) => Response::Read(key, signature, timestamp, Some((key_sig, payload)),
                    DBResponse::File(None) => {
                        let timestamp = now();
                        let id = Id::hash(&(key, timestamp, Id::MIN));
                        Response::Read(secret.sign(id), timestamp, None)
                    },
                    _ => panic!("Bad DBResponse")
                }
            },
            Request::Send(recipient, payload) => {
                let timestamp = now();
                let signature = secret.sign(Id::hash(&(recipient, timestamp, &payload)));
                self.database(DBRequest::InboxWrite(recipient, timestamp, signature, payload));
                Response::Created(signature, timestamp)
            },
            Request::Receive(signed, subscribe) => {
                let identity = resolver.resolve(signed.signer, None).await;
                match signed.verify(&identity, &[]) {
                    Ok(()) => match self.database(DBRequest::InboxRead(signed.signer, signed.payload)) {
                        DBResponse::InboxRead(inbox) => Response::Inbox(inbox),
                        _ => panic!("Bad DBResponse")
                    },
                    Err(e) => Response::InvalidSignature(e.to_string())
                }
            }
        }
    }
}

pub enum Event {
    Created(u64),
    Received(Name, u64, Vec<u8>),
    EmptyResponse(u64),
    Garbage,
}

pub struct Midstate(Option<Id>);

#[derive(Serialize, Deserilaize, Clone, Debug)]
pub struct Channel {
    location: Location,
    timestamp: u64,
    index: u64,
}

impl Channel {
    pub fn new(location: Location) -> Self {Channel{location, timestamp: 0, index: 0}}
    pub fn request(&self, secret: &Secret, outgoing: Option<Vec<u8>>) -> (Midstate, Request) {
        let key = self.location.key.derive(&[Id::hash(&self.location.server)]).derive(&[Id::hash(&self.index)]);
        let public = key.public_key();

        match outgoing {
            Some(outgoing) => {
                //TODO: verify inefficent
                let signed = postcard::to_allocvec(&Signed::new(&secret, &outgoing)).unwrap();
                let encrypted = postcard::to_allocvec(&public.encrypt(signed)).unwrap();
                (Midstate(Some(Id::hash(&encrypted))), Request::Create(KeySigned::new(&key, encrypted)))
            },
            None => (Midstate(None), Request::Read(public, true))
        }
    }

    //Returns a vector of Event to allow for the case where when writing I also know I have no
    //reads and emit an EmptyResponse(time-1) as a hack
    pub fn response(&mut self, resolver: &mut Resolver, midstate: Midstate, response: Response) -> Vec<Event> {
        let (signature, time, hash, data) = match (midstate.0, response) {
            (Some(hash), Response::Create(signature, time)) => (signature, time, hash, None),
            (_, Response::Read(signature, time, Some(data))) => (signature, time, Id::hash(&data.1), Some(data)),
            (None, Response::Read(signature, time, None)) => (signature, time, Id::MIN, None),
            _ => {return vec![Event::Garbage];}
        };
        let identity = resolver.resolve(self.location.server, Some(time)).await;
        if signature.verify(&identity, &[], Id::hash(&(public, time, hash))).is_ok() {
            index += 1;
            if time > timestamp {
                timestamp = time;
                match (hash, data) {
                    (Id::MIN, None) => {return vec![Event::EmptyResponse(time)];},
                    (_, None) => {return vec![Event::EmptyResponse(time-1), Event::Created(time)];},
                    (hash, Some((key_sig, payload))) && public.verify(key_sig, hash).is_ok() {
                        if let Some(signed) = postcard::from_bytes::<KeyEncrypted>(&payload).ok().and_then(|e|
                            key.decrypt(e).ok().and_then(|d|
                                postcard::from_bytes::<Signed<Vec<u8>>>(&d).ok()
                            )
                        ) {
                            let identity = resolver.resolve(signed.signer, Some(time)).await;
                            if signed.verify(&identity, &self.location.path).is_ok() {
                                return vec![Event::Received(signed.signer, time, signed.payload)];
                            }
                        }
                    }
                }
            }
        }
        vec![Event::Garbage]
    }
}
