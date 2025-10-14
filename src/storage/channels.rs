use orange_name::{Name, secp256k1::SecretKey, Id};

use crate::server::{Error as PurserError, Command, Context, PurserRequest};
use crate::{DateTime, now};

use std::collections::BTreeMap;
use std::fmt::Debug;

use serde::{Serialize, Deserialize};

use super::{PrivateItem, ReadPrivateItem, CreateReadPrivateItem};

#[derive(Serialize, Deserialize, Clone, Debug, Hash, PartialEq, Eq)]
pub struct Channel {
    pub key: SecretKey,
    pub servers: Vec<Name>,
}

#[derive(Default)]
pub struct Info {
    date: DateTime,//Latest Valid Date
    index: usize,//Latest(regardless of validity)
    valid: Vec<usize>,
}
impl Info {
    pub fn validate(&mut self, index: usize, date: DateTime) -> bool {
        //If valid already contains this index its likely another command ran validate just prior
        //to this with the same record
        if !self.valid.contains(&index) && (self.date - date).num_minutes().abs() > 1 || self.date < date {
            self.date = date;
            self.valid.push(index);
            true
        } else {self.valid.contains(&index)}
    }
}

pub trait Discovery: Fn(usize) -> usize + Send {}
impl<D: Fn(usize) -> usize + Send> Discovery for D {}

#[derive(Default)]
pub struct Cache {
    info: BTreeMap<Id, Info>
}

pub struct Create {
    channel: Channel,
    payload: Vec<u8>,
    target: Option<usize>,//If no target is specified discover until create is possible
    discovery: Box<dyn Discovery>,
}
impl Create {
    pub fn new(channel: Channel, payload: Vec<u8>, target: Option<usize>, discovery: impl Discovery + 'static) -> Self {
        Create{channel, target, payload, discovery: Box::new(discovery)}
    }
}
impl Command<PurserRequest> for Create {
    ///None: Successful Create
    ///Some(None): Unsuccessful Create and Read
    ///Some(Some(PrivateItem)): Unsuccessful Create but Successful Read
    type Output = Result<(Vec<PrivateItem>, bool), PurserError>;

    async fn run(self, mut ctx: Context) -> Self::Output {
        let id = Id::hash(&self.channel);

        let mut results = vec![];

        let len = ctx.get_mut_or_default::<Cache>().await.info.entry(id).or_default().valid.len();
        if let Some(t) = self.target && t > len {//Not yet reached target so read t-1
            let (r, target) = ctx.run(
                Read::new(self.channel.clone(), Some(t-1), self.discovery)
            ).await?;
            results.extend(r);
            if target.is_none() {return Ok((results, false));}
        }


        //Check if target has already been taken(Could have been found out by the Read call)
        let len = ctx.get_mut_or_default::<Cache>().await.info.entry(id).or_default().valid.len();
        if let Some(t) = self.target && len > t {return Ok((results, false));}
                
        loop {
            let index = ctx.get_mut_or_default::<Cache>().await.info.entry(id).or_default().index;
            let key = self.channel.key.derive(&[index]);
            let date = now();
            let response = ctx.run(CreateReadPrivateItem(
                key,
                PrivateItem::new(key, date, self.payload.clone()),
                self.channel.servers.clone()
            )).await?;

            let mut cache = ctx.get_mut_or_default::<Cache>().await;
            let info = cache.info.entry(id).or_default();
            info.index += 1;//Increase latest index
                    
            match response {
                Some(Some(item)) => {
                    info.validate(info.index-1, item.datetime);
                    results.push(item);
                },
                Some(None) => {},
                None => {
                    info.validate(info.index-1, date);
                    return Ok((results, true));
                }
            }
        }
    }
}

pub struct Read {
    pub channel: Channel,
    pub target: Option<usize>,
    pub discovery: Box<dyn Discovery>,
}
impl Read {
    pub fn new(channel: Channel, target: Option<usize>, discovery: impl Discovery + 'static) -> Self {
        Read{channel, target, discovery: Box::new(discovery)}
    }
}
impl Command<PurserRequest> for Read {
    ///Vector of new items, Option index on the new items vec that is your target
    type Output = Result<(Vec<PrivateItem>, Option<usize>), PurserError>;

    async fn run(self, mut ctx: Context) -> Self::Output {
        let id = Id::hash(&self.channel);

        if let Some(t) = self.target {
            let t = ctx.get_mut_or_default::<Cache>().await.info.entry(id).or_default().valid.get(t).copied();
            if let Some(index) = t {
                let r = ctx.run(
                    ReadPrivateItem(self.channel.key.derive(&[index]), self.channel.servers.clone())
                ).await?;
                //If we had this index cached then the item exists and is valid
                return Ok((vec![r.expect("Blame Air Servers").expect("Blame Air Servers")], Some(0)));
            }
        }

        let mut results = vec![];
        let mut count = 1;
        let mut f_target = None;

        loop {
            let index = ctx.get_mut_or_default::<Cache>().await.info.entry(id).or_default().index;

            let requests = (index..(index+count)).map(|i| {
                ReadPrivateItem(self.channel.key.derive(&[i]), self.channel.servers.clone())
            }).collect::<Vec<_>>();
            let r = ctx.run(requests).await.into_iter().collect::<Result<Vec<_>, PurserError>>()?;

            let mut cache = ctx.get_mut_or_default::<Cache>().await;
            let info = cache.info.entry(id).or_default();
            for r in r {
                match r {
                    None => {return Ok((results, f_target));}
                    Some(taken) => {
                        info.index += 1;//Increase Channel Index(regardless of validity)
                        if let Some(item) = taken {
                            if info.validate(info.index-1, item.datetime) {
                                results.push(item);
                                if let Some(t) = self.target && info.valid.len()-1 == t {
                                    f_target = Some(results.len()-1);
                                }
                            }
                        }
                    }
                }
            }
            if let Some(r) = f_target {return Ok((results, Some(r)))}
            count = (self.discovery)(count);
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::server::{Compiler, PurserRequest, Purser};

    async fn run<T: Send + 'static, C: Command<PurserRequest, Output = T>>(cache: Cache, cmd: C) -> (Cache, T) {
        let mut c = Compiler::new(Purser::new());
        c.store().await.insert(cache);
        c.add_task(0, cmd);
        let (mut s, mut r) = c.run().await;
        (s.remove::<Cache>().unwrap(), r.remove(&0).unwrap())
    }

    #[tokio::test]
    async fn create_read() {
        let channel = Channel{
            key: SecretKey::new(),
            servers: vec![Name::orange_me()],
        };
        let id = Id::hash(&channel);
        let payload = b"hello".to_vec();
        let (cache, r) = run(Cache::default(), Create::new(channel.clone(), payload.clone(), None, |i| i+1)).await;
        let (r, s) = r.unwrap();
        assert_eq!(s, true);
        assert_eq!(r, vec![]);
        let info = cache.info.get(&id).unwrap();
        assert_eq!(info.index, 1);
        assert_eq!(info.valid.len(), 1);

        let (cache, r) = run(Cache::default(), Read::new(channel.clone(), Some(4), |i| i+4)).await;
        let (r, s) = r.unwrap();
        assert_eq!(s, None);
        assert_eq!(r.len(), 1);
        let info = cache.info.get(&id).unwrap();
        assert_eq!(info.index, 1);
        assert_eq!(info.valid.len(), 1);
    }

    #[tokio::test]
    async fn out_of_order() {
        let channel = Channel{
            key: SecretKey::new(),
            servers: vec![Name::orange_me()],
        };
        let id = Id::hash(&channel);
        let payload = b"bad hello".to_vec();
        let cache = Cache{
            info: BTreeMap::from([(id, Info{index: 1, date: DateTime::UNIX_EPOCH, valid: vec![]})])
        };
        let (cache, r) = run(cache, Create::new(channel.clone(), payload, None, |i| i+1)).await;
        let (r, s) = r.unwrap();
        assert_eq!(s, true);
        assert_eq!(r, vec![]);
        let info = cache.info.get(&id).unwrap();
        assert_eq!(info.index, 2);
        assert_eq!(info.valid.len(), 1);

        let payload = b"good hello".to_vec();
        let (cache, r) = run(Cache::default(), Create::new(channel.clone(), payload.clone(), None, |i| i+1)).await;
        let (r, s) = r.unwrap();
        assert_eq!(s, true);
        assert_eq!(r, vec![]);
        let info = cache.info.get(&id).unwrap();
        assert_eq!(info.index, 1);
        assert_eq!(info.valid.len(), 1);

        let (cache, r) = run(Cache::default(), Read::new(channel.clone(), None, |i| i+1)).await;
        let (r, s) = r.unwrap();
        assert_eq!(s, None);
        assert_eq!(r.len(), 1);
        let info = cache.info.get(&id).unwrap();
        assert_eq!(info.index, 2);
        assert_eq!(info.valid.len(), 1);
    }
}
