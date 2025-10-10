use orange_name::{Name, secp256k1::{SecretKey, Signed as KeySigned, PublicKey}, Id, Secret};

use crate::server::{Error as PurserError, Command, Context, PurserRequest};
use crate::storage::{CreatePrivate, CreateReadPrivate, ReadPrivate, ReadPrivateHash};

use std::hash::{Hasher, Hash};
use std::time::Duration;
use std::path::PathBuf;

use crate::{DateTime, now};

use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Clone, Debug, Hash, PartialEq, Eq)]
pub struct PrivateItem {
    pub discover: PublicKey,
    pub datetime: DateTime,
    pub payload: Vec<u8>,
}

impl PrivateItem {
    pub fn new(key: SecretKey, datetime: DateTime, payload: Vec<u8>) -> KeySigned<PrivateItem> {
        let discover = key.public_key();
        KeySigned::new(&key, PrivateItem{
            discover,
            payload: discover.encrypt(payload).unwrap(),
            datetime
        })
    }

    pub fn decrypt(item: KeySigned<PrivateItem>, key: &SecretKey) -> Result<Self, secp256k1::Error> {
        let discover = key.public_key();
        let mut item = item.verify().and_then(|signer| {
            (signer == discover && item.as_ref().discover == discover)
            .then_some(item.into_inner()).ok_or(secp256k1::Error::InvalidMessage)
        })?;
        item.payload = key.decrypt(&item.payload)?;
        Ok(item)
    }
}

pub struct Create(pub KeySigned<PrivateItem>, pub Vec<Name>);
impl Command<PurserRequest> for Create {
    type Output = Result<Option<(DateTime, Id)>, PurserError>;

    async fn run(self, mut ctx: Context) -> Self::Output {
        let request = CreatePrivate(self.0);
        let r: Option<Result<Option<(DateTime, Id)>, PurserError>> = majority(ctx.run((request, self.1)).await);
        //TODO: If no majority was found entry recovery mode
        r.ok_or(PurserError::mr("No Majority Response")).flatten()
    }
}

#[derive(Debug)]
pub struct CreateRead(pub SecretKey, pub KeySigned<PrivateItem>, pub Vec<Name>);
impl Command<PurserRequest> for CreateRead {
    type Output = Result<Option<Option<PrivateItem>>, PurserError>;

    async fn run(mut self, mut ctx: Context) -> Self::Output {
        let fs = self.2.pop().ok_or(PurserError::ConnectionFailed("No Servers".to_string()))?;
        let (payload, others) = ctx.run((
            (CreateReadPrivate(self.1.clone()), fs),
            (CreatePrivate(self.1), self.2.clone())
        )).await;
        let results = others.into_iter().zip(self.2).map(|(r, n)|
            r.map(|p| p.map(|(_, h)| (h, n)))
        ).collect::<Vec<_>>();
        read(&mut ctx, &self.0, payload, results).await
    }
}

#[derive(Debug)]
pub struct Read(pub SecretKey, pub Vec<Name>);
impl Command<PurserRequest> for Read {
    type Output = Result<Option<Option<PrivateItem>>, PurserError>;

    async fn run(mut self, mut ctx: Context) -> Self::Output {
        let fs = self.1.pop().ok_or(PurserError::ConnectionFailed("No Servers".to_string()))?;
        let (payload, others) = ctx.run((
            (ReadPrivate(KeySigned::new(&self.0, ())), fs),
            (ReadPrivateHash(KeySigned::new(&self.0, ())), self.1.clone())
        )).await;
        let results = others.into_iter().zip(self.1).map(|(r, n)|
            r.map(|p| p.map(|(_, h)| (h, n)))
        ).collect::<Vec<_>>();
        read(&mut ctx, &self.0, payload, results).await
    }
}

fn majority<R: PartialEq>(responses: Vec<R>) -> Option<R> {
    let req = (responses.len() / 2) + 1;
    let (count, winner) = responses.into_iter().fold((1, None), |mut acc, p| {
        if acc.0 == 1 {acc.0 = 1; acc.1 = Some(p);}
        else if acc.1 == Some(p) {acc.0 += 1;}
        else {acc.0 -= 1;}
        acc
    });
    if count >= req {Some(winner.unwrap())} else {None}
}


async fn read(
    ctx: &mut Context,
    key: &SecretKey,
    payload: Result<Option<(Id, KeySigned<PrivateItem>)>, PurserError>,
    results: Vec<Result<Option<(Id, Name)>, PurserError>>
) -> Result<Option<Option<PrivateItem>>, PurserError> {
    let mut hashes = results.iter().map(|r| r.as_ref().map(|o| o.map(|(i, _)| i)).map_err(|e| e.clone())).collect::<Vec<_>>();
    hashes.push(payload.as_ref().map(|o| o.as_ref().map(|(i, _)| *i)).map_err(|e| e.clone()));
    if let Some(hash) = majority(hashes).ok_or(PurserError::mr("No Majority Response"))?? {
        let mut servers: Vec<Name> = results.into_iter().filter_map(|i|
            i.ok().flatten().filter(|(h, _)| *h == hash).map(|(_, n)| n)
        ).collect::<Vec<_>>();

        let mut payload = payload.ok().flatten().filter(|(i, _)| *i == hash).map(|(_, p)| p);
        if payload.is_none() {
            for server in servers {
                let result = ctx.run((ReadPrivate(KeySigned::new(key, ())), server)).await;
                match result {
                    Ok(Some((id, p))) if id == hash => {payload = Some(p);},
                    Err(PurserError::Disconnected) => Err(PurserError::Disconnected)?,
                    Err(PurserError::ConnectionFailed(s)) => Err(PurserError::ConnectionFailed(s))?,
                    _ => {}//TODO: blame the air server
                }
            }
        }
        let payload = payload.ok_or(PurserError::mr("All Air servers claimed to have a record hash and won't provide payload"))?;
        //Extract the PrivateItem
        Ok(Some(PrivateItem::decrypt(payload, key).ok()))
    } else {Ok(None)}
}


#[cfg(test)]
mod test {
    use super::*;
    use crate::server::{Compiler, PurserRequest, Purser};

    async fn run<T: Send + 'static, C: Command<PurserRequest, Output = T>>(cmd: C) -> T {
        let mut compiler = Compiler::new(Purser::new());
        compiler.add_task(0, cmd);
        compiler.run().await.remove(&0).unwrap()
    }

    #[tokio::test]
    async fn test_private_item() {
        let key = SecretKey::new();
        let datetime = now();
        let payload = b"hello".to_vec();
        let item = PrivateItem::new(key, datetime, b"hello".to_vec());
        let hash = Id::hash(&item);
        assert_eq!(run(Create(item.clone(), vec![Name::orange_me()])).await, Ok(None));
        assert_eq!(run(Create(item.clone(), vec![Name::orange_me()])).await, Ok(Some((datetime, hash))));

        let mut decrypted_item = item.clone().into_inner();
        decrypted_item.payload = payload;

        assert_eq!(run(CreateRead(key, item.clone(), vec![Name::orange_me()])).await, Ok(Some(Some(decrypted_item.clone()))));

        assert_eq!(run(Read(key, vec![Name::orange_me()])).await, Ok(Some(Some(decrypted_item))));
    }
}
