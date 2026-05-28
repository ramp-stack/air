use serde::{Serialize, Deserialize};

use crate::names::{secp256k1::{Signed as KeySigned, SecretKey, Encrypted as KeyEncrypted}, Resolver, Signed, Secret, Name, Encrypted, Id, now};
use crate::{Purser, Request, Response};

use std::collections::BTreeMap;

use crossfire::{MAsyncTx, AsyncTx, AsyncRx, mpsc, spsc};
use tokio::spawn;

use crate::instance::Location;
use crate::storage::Compare;

#[derive(Debug)]
pub struct InboxHandler(Inbox, AsyncRx<spsc::List<(u64, Option<Location>)>>);
impl InboxHandler {
    pub fn inbox(&self) -> &Inbox {&self.0}

    pub async fn read(&mut self) -> (u64, Option<Location>) {
        let (time, data) = self.1.recv().await.unwrap();
        self.0.0 = time;
        (time, data)
    }

    pub async fn read_all(&mut self) -> BTreeMap<u64, Location> {
        let mut results = BTreeMap::new();
        while let Ok((time, data)) = self.1.try_recv() {
            self.0.0 = time;
            if let Some(data) = data {
                results.insert(time, data);
            }
        }
        results
    }

    pub async fn send(purser: &Purser, resolver: &mut Resolver, name: Name, location: Location) {
        let identity = resolver.resolve(name, None).await;
        let home = *identity.servers().first().unwrap();
        let conn = purser.connect(home).await.unwrap();
        //Verify receipet
        conn.send(Request::Send(name, postcard::to_allocvec(&identity.encrypt(&[], postcard::to_allocvec(&location).unwrap())).unwrap())).await;
    }
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, Default)]
pub struct Inbox(u64);
impl Inbox {
    pub fn start(mut self, mut resolver: Resolver, purser: Purser, secret: Secret) -> InboxHandler {
        let (tx, rx): (AsyncTx<_>, _) = spsc::build(spsc::List::new());

        spawn(async move { loop {
            let identity = resolver.resolve(secret.name(), None).await;
            let home = *identity.servers().first().unwrap();
            let conn = purser.connect(home).await.unwrap();
            match conn.send(Request::Receive(Signed::new(&secret, (Compare::Greater, self.0)))).await {
                Response::Inbox(received) => {
                    let home_identity = resolver.resolve(home, None).await;
                    for (signature, timestamp, data) in received {
                        if signature.verify(&home_identity, &[], Id::hash(&(secret.name(), timestamp, &data))).is_ok() && timestamp > self.0 {
                            self.0 = timestamp;
                            let data = postcard::from_bytes::<Encrypted>(&data).ok().and_then(|d| postcard::from_bytes::<Location>(&secret.decrypt(d).ok()?).ok());
                            tx.send((timestamp, data)).await.unwrap();
                        } else {panic!("Bad Air Server");}
                    }
                },
                response => {panic!("Bad Air Server: {response:?}");}
            }
        }});
        InboxHandler(self, rx)
    }
}
