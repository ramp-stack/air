use easy_secp256k1::EasySecretKey;
use secp256k1::SecretKey;
use super::{ValidationError, Error};
use super::{Command, Cache, WSecretKey, RecordPath, PathedKey, Processed, AnyResult, Task, ProtocolGen, _ProtocolGen, Endpoints, Id};
use crate::storage::requests;
use crate::storage::records::{self, Header, Record, KeySet, Key, ReadResult};
use crate::server::Request;
use crate::did::Endpoint;
use std::collections::BTreeMap;
use std::hash::Hash;
use std::fmt::Debug;

#[derive(Debug, PartialEq, Eq, Hash)]
pub struct Wait<C: Command>(pub Option<C>, pub usize);
impl<C: Command> Wait<C> {
    pub fn new(c: C, wait: usize) -> Self {Wait(Some(c), wait)}
}
impl<C: Command + Debug + Hash + Eq> Command for Wait<C> {
    type Output = C::Output;

    fn process(mut self: Box<Self>, _cache: &mut Cache, _key: &PathedKey, mut params: Vec<Result<Box<dyn AnyResult>, Error>>) -> Result<Processed, Error> {
        if self.1 > 0 {
            let wait = Wait(self.0.take(), self.1-1);
            self.1 = 0;
            Ok(Processed::Waiting(self, vec![Task::run(wait)]))
        } else if !params.is_empty() {
            Ok(Processed::Complete(params.remove(0)))
        } else {
            let cmd = self.0.take().unwrap();
            Ok(Processed::Waiting(self, vec![Task::run(cmd)]))
        }
    }
}

#[derive(Debug, PartialEq, Eq, Hash)]
pub enum Discover{
    New(RecordPath, Option<u32>, u32, Endpoint),
    Loop(RecordPath, (WSecretKey, Option<WSecretKey>), u32, u32, u32, Endpoint, Vec<Record>)
}
impl Discover {pub fn new(path: RecordPath, start: Option<u32>, gap: u32, endpoint: Endpoint) -> Self {
    Discover::New(path, start, gap, endpoint)
}}
impl Command for Discover {
    type Output = Vec<Record>;

    fn process(mut self: Box<Self>, cache: &mut Cache, key: &PathedKey, mut params: Vec<Result<Box<dyn AnyResult>, Error>>) -> Result<Processed, Error> {
        Ok(match *self {
            Discover::New(path, mut start, gap, endpoint) => {
                let (parent, index) = cache.get(&path.last()).ok_or(ValidationError::MissingRecord(path.to_string()))?;
                let start = start.unwrap_or(index);
                let children = parent.0.children.and_then(|(d, r)| d.secret().map(|d| (d, r))).ok_or(ValidationError::InvalidParent(path.to_string()))?;
                let task = Task::request(Request::Read(children.0.easy_derive(&[start])?.into()), endpoint.clone());
                Processed::Waiting(Box::new(Discover::Loop(path, (children.0, children.1.secret()), start, gap, 0, endpoint, vec![])), vec![task])
            },
            Discover::Loop(path, (discover_child, read_child), mut start, gap, mut empty, endpoint, mut records) => {
                start += 1;
                if let Some(item) = params.remove(0)?.try_into::<<requests::ReadPrivate as Request>::Output>().unwrap()? {
                    cache.cache_index(&path.last(), start);
                    if let Some(read) = read_child.map(|r| r.easy_derive(&[start-1])).transpose()? {
                        if let Ok(record) = Record::from_item(item, read) {
                            cache.cache(record.header.clone(), 0);
                            records.push(record);
                        }
                    }
                    empty = 0;
                } else {empty += 1;}
                if empty >= gap {return Ok(Processed::Complete(Ok(Box::new(records))));}
                let task = Task::request(Request::Read(discover_child.easy_derive(&[start])?.into()), endpoint.clone());
                Processed::Waiting(Box::new(Discover::Loop(path, (discover_child, read_child), start, gap, empty, endpoint, records)), vec![task])
            }
        })
    }
}

#[derive(Debug, PartialEq, Eq, Hash)]
pub enum Create{
    New(RecordPath, Box<dyn ProtocolGen>, Vec<u8>, u32, Endpoint),
    Create(RecordPath, Box<dyn ProtocolGen>, Vec<u8>, Endpoint, Option<Header>),
}
impl Command for Create {
    type Output = Id;

    fn process(self: Box<Self>, cache: &mut Cache, key: &PathedKey, mut params: Vec<Result<Box<dyn AnyResult>, Error>>) -> Result<Processed, Error> {
        Ok(match *self {
            Create::New(parent, protocol, payload, gap, endpoint) => {
                let task = Task::run(Discover::new(parent.clone(), None, gap, endpoint.clone()));
                Processed::Waiting(Box::new(Create::Create(parent, protocol, payload, endpoint, None)), vec![task])
            },
            Create::Create(path, protocol, payload, endpoint, header) => {
                if let Some(create) = params.remove(0)?.try_into::<<requests::Create as RequestTrait>::Output>() {
                    if create?.is_none() {
                        let header = header.unwrap();
                        let id = Id::from(&header);
                        cache.cache(header, 0);
                        return Ok(Processed::Complete(Ok(Box::new(id))));
                    }
                }
                let index = cache.get_index(&path.last());
                cache.cache_index(&path.last(), index+1);
                let header = protocol.header(cache, &key.derive(&path)?, index)?;
                let record = Record{header: header.clone(), payload: payload.clone()};
                let task = Task::request(Request::Create(record), endpoint.clone());
                Processed::Waiting(Box::new(Create::Create(path, protocol, payload, endpoint, Some(header))), vec![task])
            }
        })
    }
}

#[derive(Debug, PartialEq, Eq, Hash)]
pub struct Read(pub RecordPath, pub Endpoint);
impl Command for Read {
    type Output = Option<Record>;

    fn process(self: Box<Self>, cache: &mut Cache, key: &PathedKey, mut params: Vec<Result<Box<dyn AnyResult>, Error>>) -> Result<Processed, Error> {
        let (header, _) = cache.get(&self.0.last()).ok_or(ValidationError::MissingRecord(self.0.to_string()))?;
        Ok(if params.is_empty() {
            let task = Task::request(Request::Read(header.0.discover), self.1.clone());
            Processed::Waiting(self, vec![task])
        } else {
            let record = params.remove(0)?.try_into::<<requests::ReadPrivate as RequestTrait>::Output>().unwrap()?.map(|item|  {
                let record = Record::from_item(item, *header.0.read)?;
                if Id::from(&record.header) != Id::from(&header) {return Err(Error::CorruptedRecord(self.0.clone(), None));}
                Ok(record)
            }).transpose()?;
            Processed::Complete(Ok(Box::new(record)))
        })
    }
}
