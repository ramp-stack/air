use crate::names::{Id, Secret, Resolver, Signed, Name, secp256k1::SecretKey, now};

use crate::{Purser, Inbox, InboxHandler, channel, Channel, Response, Request as StorageRequest, Compare};

use std::collections::{HashMap, HashSet, BTreeMap};
use std::path::{PathBuf, Path};
use std::hash::Hash;
use std::any::TypeId;
use std::sync::Arc;

use serde::{Serialize, Deserialize};
use crate::substance::{Substance, Beaker, into, from, Offset, Logger};

use crossfire::{MAsyncTx, MAsyncRx, AsyncTx, AsyncRx, mpsc, mpmc, spsc};
use tokio::spawn;

use futures_util::stream::FuturesUnordered;
use futures_util::StreamExt;
use rusqlite::{Connection, OptionalExtension};

use std::pin::Pin;
use arc_swap::ArcSwap;

#[derive(Debug)]
pub enum Error {
    UnregisteredContract(Id),
    MissingInstance(Id),
    InvalidReactant,
}
impl std::error::Error for Error {}
impl std::fmt::Display for Error {fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {write!(f, "{self:?}")}}

pub trait Reactant: Serialize + for<'a> Deserialize<'a> {
    type Error: std::error::Error;

    fn apply<B: Beaker>(self, path: &Path, signer: &Name, timestamp: u64, substance: &mut B) -> Result<(), Self::Error>;
}

pub trait Contract: Serialize + for<'a> Deserialize<'a> + Hash {
    fn id() -> Id;

    fn init(self, signer: &Name, timestamp: u64) -> Substance;

    fn routes() -> BTreeMap<PathBuf, Reactants>;
}

#[derive(Default, Debug, Clone)]
pub struct Reactants(Vec<ErasedReactant>);
impl Reactants {
    pub fn add<R: Reactant + 'static>(mut self) -> Self {
        self.0.push(ErasedReactant::erase::<R>());
        self
    }

    fn index<R: Reactant + 'static>(&self) -> Option<usize> {
        let id = TypeId::of::<R>();
        self.0.iter().position(|r| r.type_id == id)
    }

    fn get(&self, index: usize) -> Option<&ErasedReactant> {self.0.get(index)}
}

#[derive(Default)]
pub struct Contracts(pub(crate) HashMap<Id, ErasedContract>);
impl Contracts {
    pub fn add<C: Contract + 'static>(mut self) -> Self {
        self.0.insert(C::id(), ErasedContract::erase::<C>()); self
    }
}

#[derive(Clone)]
pub struct ErasedReactant {
    type_id: TypeId,
    pub apply: Arc<Box<dyn Fn(&[u8], &Path, &Name, u64, &mut Offset<Logger<Substance>>) -> bool + Send + Sync>>,
    name: String,
}

impl ErasedReactant {
    pub fn erase<R: Reactant + 'static>() -> Self {ErasedReactant{
        type_id: TypeId::of::<R>(),
        apply: Arc::new(Box::new(|b: &[u8], path: &Path, signer: &Name, timestamp: u64, logger: &mut Offset<Logger<Substance>>| {
            println!("bytes: {:?}", b);
            match postcard::from_bytes::<R>(b) {
                Err(e) => {println!("Invalid Reactant: {:?}", e); false},
                Ok(r) => match r.apply(path, signer, timestamp, logger) {
                    Err(e) => {println!("Reactant Error: {:?}", e); false},
                    Ok(()) => true
                }
            }
            })),
        name: std::any::type_name::<R>().to_string()
    }}
}
impl std::fmt::Debug for ErasedReactant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("ErasedReactant").field(&self.name).finish()
    }
}

#[derive(Clone)]
pub struct ErasedContract {
    pub id: Id,
    pub init: Arc<Box<dyn Fn(&[u8], &Name, u64) -> Result<Substance, postcard::Error> + Send + Sync>>,
    routes: BTreeMap<PathBuf, Reactants>,
}
impl ErasedContract {
    pub fn erase<C: Contract + 'static>() -> Self {ErasedContract{
        id: C::id(),
        init: Arc::new(Box::new(|b: &[u8], signer: &Name, timestamp: u64|
            postcard::from_bytes::<C>(b).map(|c| c.init(signer, timestamp))
        )),
        routes: C::routes()
    }}

    pub fn index<R: Reactant + 'static>(&self, path: &Path) -> Option<usize> {
        self.routes.get(path).and_then(|r| r.index::<R>())
    }

    pub fn get(&self, path: &Path, index: usize) -> Option<&ErasedReactant> {
        self.routes.get(path).and_then(|r| r.get(index))
    }
}
impl std::fmt::Debug for ErasedContract {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ErasedContract").field("id", &self.id).field("routes", &self.routes).finish()
    }
}

pub struct Cache(rusqlite::Connection);
impl Cache {
    pub fn new<P: AsRef<Path>>(path: P) -> Result<Self, rusqlite::Error> {
        let mut conn = if cfg!(test) {
            rusqlite::Connection::open(format!("file:mem_{}?mode=memory", Id::hash(&path.as_ref().to_path_buf())))?
        } else {
            rusqlite::Connection::open(path)?
        };
        conn.pragma_update(None, "locking_mode", "EXCLUSIVE")?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Exclusive)?;
        tx.execute("CREATE TABLE if not exists Cache(
            key TEXT NOT NULL PRIMARY KEY,
            value BLOB NOT NULL
        );", [])?;
        tx.commit()?;
        Ok(Cache(conn))
    }
    pub fn get<T: for<'a> Deserialize<'a>>(&self, key: &str) -> Result<Option<T>, rusqlite::Error> {
        Ok(self.0.query_row(
            &format!("SELECT value FROM Cache WHERE key='{key}'"),
            [], |r| Ok(postcard::from_bytes(&r.get::<_, Vec<u8>>(0)?).ok()),
        ).optional()?.flatten())
    }

    pub fn insert<T: Serialize>(&mut self, key: &str, value: &T) -> Result<(), rusqlite::Error> {
        self.0.execute(
            &format!("INSERT INTO Cache(key, value) VALUES ('{key}', ?1) ON CONFLICT DO UPDATE SET value=excluded.value;"),
            [postcard::to_allocvec(value).unwrap()],
        )?;
        Ok(())
    }
}
