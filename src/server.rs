use crate::names::{Secret, Signature, Id};
use crate::names::secp256k1::{Signature as KeySignature};

use crate::storage::{Storage, Request, Response, DBRequest, DBResponse, Subscriptions};

use crate::websocket::{Socket, Stream, Sink};

use crossfire::{MAsyncTx, AsyncRx, spsc, mpsc};
use rusqlite::{Connection, params, OptionalExtension};

use std::collections::HashMap;

type Responder = MAsyncTx<spsc::List<(u64, Signature, Response)>>;
type StorageRequest = ((u64, u64), Request, Responder);

#[derive(Clone)]
pub struct Server;
impl Server {
    pub async fn start(secret: Secret) {
        let (tx, rx): (MAsyncTx<_>, _) = mpsc::build(mpsc::List::new());
        let s = secret.clone();
        tokio::spawn(async move {Self::storage(&s, rx).await});

        let mut s_count = 0;
        Socket::listen(&secret, |socket| {
            s_count += 1;
            let (sp, sc) = mpsc::build(mpsc::List::new());

            tokio::spawn(async move { Self::write(socket.0, sc).await});
            let tx = tx.clone();
            tokio::spawn(async move {Self::read(s_count, socket.1, tx, sp).await});
        }).await
    }

    async fn read(s_count: u64, mut stream: Stream, tx: MAsyncTx<mpsc::List<StorageRequest>>, responder: Responder) {
        loop {
            let (r_count, bytes) = stream.read().await;
            if let Ok(request) = postcard::from_bytes(&bytes) {
                tx.send(((s_count, r_count), request, responder.clone())).await.unwrap();
            }
        }
    }

    async fn storage(secret: &Secret, rx: AsyncRx<mpsc::List<StorageRequest>>) {
        let mut subscriptions = Subscriptions::default();
        let mut responders = HashMap::new();
        let mut cache = Cache::new();
        while let Ok(((s_count, r_count), request, responder)) = rx.recv().await {
            responders.insert(s_count, responder);
            let hash = Id::hash(&request);
            println!("r_count: {:?}: {:?}", r_count, hash);
            let (output, response) = Storage::run(request, |r| cache.store(r)).await;
            let responses = subscriptions.process((s_count, r_count, hash), output, response);
            for ((s_count, r_count, hash), response) in responses {
                println!("s_count: {:?}: {:?}", s_count, r_count);
                let _ = responders.get(&s_count).unwrap().send((r_count, secret.sign(Id::hash(&(hash, Id::hash(&response)))), response)).await;
            }
            responders.extract_if(|_, responder| responder.get_rx_count() == 0).for_each(|(s, _)| subscriptions.close_socket(s));
        }
    }

    async fn write(mut sink: Sink, rx: AsyncRx<spsc::List<(u64, Signature, Response)>>) {
        while let Ok((index, sig, response)) = rx.recv().await {
            sink.write(Some(index), postcard::to_allocvec(&(sig, response)).unwrap()).await;
        }
    }
}

pub struct Cache(Connection);
impl Default for Cache {fn default() -> Self {Self::new()}}
impl Cache {
    pub fn new() -> Self {
        let connection = Connection::open("STORAGE.db").unwrap();

        connection.execute("CREATE TABLE if not exists private(
            key TEXT NOT NULL UNIQUE,
            key_signature BLOB NOT NULL,
            timestamp BLOB NOT NULL,
            payload BLOB NOT NULL
        );", []).unwrap();

        Cache(connection)
    }

    pub fn store(&mut self, request: &DBRequest) -> DBResponse {match request {
        DBRequest::FileWrite(timestamp, signed) => DBResponse::File(self.0.query_row(
            "INSERT INTO private(key, timestamp, key_signature, payload)
             VALUES (?1, ?2, ?3, ?4) ON CONFLICT DO UPDATE SET key=?1
             RETURNING key_signature, timestamp, payload;",
            params![
                postcard::to_allocvec(&signed.key).unwrap(),
                postcard::to_allocvec(&timestamp).unwrap(),
                postcard::to_allocvec(&signed.signature).unwrap(),
                &signed.payload
            ],
            |row| Ok((
                postcard::from_bytes::<u64>(&row.get::<_, Vec<u8>>("timestamp")?).unwrap(),
                postcard::from_bytes::<KeySignature>(&row.get::<_, Vec<u8>>("key_signature")?).unwrap(),
                row.get::<_, Vec<u8>>("payload")?
            ))
        ).optional().unwrap().filter(|r| &r.0 != timestamp)),
        DBRequest::FileRead(key) => DBResponse::File(self.0.query_row(
            "SELECT timestamp, key_signature, payload FROM private WHERE key=?1",
            [postcard::to_allocvec(&key).unwrap()], |row| Ok((
                postcard::from_bytes::<u64>(&row.get::<_, Vec<u8>>("timestamp")?).unwrap(),
                postcard::from_bytes::<KeySignature>(&row.get::<_, Vec<u8>>("key_signature")?).unwrap(),
                row.get::<_, Vec<u8>>("payload")?
            ))
        ).optional().unwrap()),
    }}
}
