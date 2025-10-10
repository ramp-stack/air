use orange_name::{Name, secp256k1::{SecretKey, Signed as KeySigned, PublicKey}, Id, Secret};

use crate::server::{Error as PurserError, Command, Context, PurserRequest};

use std::hash::{Hasher, Hash};
use std::time::Duration;
use std::path::PathBuf;
use std::fmt::Debug;

use crate::{DateTime, now};

use serde::{Serialize, Deserialize};

use super::{PrivateItem, ReadPrivateItem, CreateReadPrivateItem};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Channel{
    index: usize,
    date: DateTime,
    key: SecretKey,
    servers: Vec<Name>
}

#[derive(Debug, PartialEq)]
pub enum Error<V> {
    PurserError(PurserError),
    Validation(V)
}
impl<V: Debug> std::error::Error for Error<V> {}
impl<V: Debug> std::fmt::Display for Error<V> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {write!(f, "{self:?}")}
}
impl<V> From<V> for Error<V> {fn from(e: V) -> Self {Self::Validation(e)}}

pub enum State {
    Read(usize),
    Create(Vec<u8>),
    Stop
}

pub struct Traverse<R, E>{
    state: State,
    channel: Channel,
    validate: Box<dyn FnMut(Vec<Option<PrivateItem>>) -> Result<(Vec<R>, Option<State>), E> + Send>,
    results: Vec<R>
}

impl Traverse<Option<PrivateItem>, ()> {
    pub fn new(channel: Channel, state: State) -> Self {
        Traverse{state, channel, validate: Box::new(|items| Ok((items, None))), results: vec![]}
    }
}
impl<R: Send + 'static, E: Send + 'static> Traverse<R, E> {
    pub fn new_with_validation(channel: Channel, state: State, validate: impl FnMut(Vec<Option<PrivateItem>>) -> Result<(Vec<R>, Option<State>), E> + Send + 'static) -> Self {
        Traverse{state, channel, validate: Box::new(validate), results: vec![]}
    }
}
impl<R: Send + 'static, E: Send + 'static> Command<PurserRequest> for Traverse<R, E> {
    type Output = Result<(Channel, Vec<R>), Error<E>>;

    async fn run(mut self, mut ctx: Context) -> Self::Output {
        let mut gap = false;
        let result = loop {
            let responses = match &self.state {
                State::Read(count) => {
                    let requests = (self.channel.index..(self.channel.index+count)).map(|i| {
                        let key = self.channel.key.derive(&[i]);
                        ReadPrivateItem(
                            key, self.channel.servers.clone()
                        )
                    }).collect::<Vec<_>>();
                    ctx.run(requests).await.into_iter()
                        .collect::<Result<Vec<_>, PurserError>>()
                        .map_err(|e| Error::PurserError(e))?.into_iter()
                        .filter_map(|r| {
                        gap = r.is_none();
                        (!gap).then(|| {
                            self.channel.index += 1;
                            r.unwrap().filter(|p| {
                            let f = (self.channel.date - p.datetime).num_minutes().abs() > 1 || 
                                self.channel.date < p.datetime;
                            if f {self.channel.date = p.datetime;}
                            f
                        })})
                    }).collect::<Vec<_>>()
                },
                State::Create(payload) => {
                    let key = self.channel.key.derive(&[self.channel.index]);
                    let response = ctx.run(CreateReadPrivateItem(
                        key,
                        PrivateItem::new(key, now(), payload.clone()),
                        self.channel.servers.clone()
                    )).await.map_err(|e| Error::PurserError(e))?;
                    self.channel.index += 1;
                    gap = response.is_none();
                    if gap {break self.results}
                    vec![response.unwrap()]
                },
                State::Stop => break self.results
            };
            let (results, new_state) = (self.validate)(responses)?;
            self.results.extend(results);
            if gap {break self.results}
            self.state = new_state.unwrap_or(self.state);
        };
        Ok((self.channel, result))
    }
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
    async fn create_read() {
        let channel = Channel{
            index: 0,
            date: DateTime::UNIX_EPOCH,
            key: SecretKey::new(),
            servers: vec![Name::orange_me()],
        };
        let payload = b"hello".to_vec();
        let (mut channel, result) = run(Traverse::new(channel, State::Create(payload.clone()))).await.unwrap();
        assert_eq!(result, vec![]);
        assert_eq!(channel.index, 1);
        channel.index = 0; 

        let (channel, mut r) = run(Traverse::new_with_validation(channel, State::Read(4), |mut items: Vec<Option<PrivateItem>>| {
            assert_eq!(items.len(), 1);
            Ok::<_, ()>((vec![items.remove(0).unwrap()], None))
        })).await.unwrap();
        assert_eq!(channel.index, 1);
        let read_item = r.remove(0);
        assert_eq!(read_item.discover, channel.key.derive(&[0 as usize]).public_key());
        assert_eq!(read_item.payload, payload);
    }

    #[tokio::test]
    async fn out_of_order() {
        let channel = Channel{
            index: 1,
            date: DateTime::UNIX_EPOCH,
            key: SecretKey::new(),
            servers: vec![Name::orange_me()],
        };
        let payload = b"bad hello".to_vec();

        let (mut channel, r) = run(Traverse::new(channel, State::Create(payload.clone()))).await.unwrap();
        assert_eq!(channel.index, 2);
        assert_eq!(r, vec![]);

        let payload = b"good hello".to_vec();
        channel.index = 0;

        let (mut channel, r) = run(Traverse::new(channel, State::Create(payload.clone()))).await.unwrap();
        assert_eq!(channel.index, 1);
        assert_eq!(r, vec![]);
        
        channel.index = 0;
        
        let (channel, mut r) = run(Traverse::new(channel, State::Read(4))).await.unwrap();
        assert_eq!(channel.index, 2);
        let read = r.remove(0).unwrap();
        assert_eq!(read.discover, channel.key.derive(&[0 as usize]).public_key());
        assert_eq!(read.payload, payload);
        assert_eq!(r.remove(0), None);
    }
}
