use rusqlite::{Connection, OptionalExtension, TransactionBehavior, OpenFlags, Error};
use serde::{Serialize, Deserialize};
use std::path::Path;
use crate::names::Id;

pub struct Cache(Connection);
impl Cache {
    pub fn new<P: AsRef<Path>>(path: P) -> Result<Self, Error> {
        let mut conn = if cfg!(test) {
            Connection::open_with_flags(
                format!("file:mem_{}?mode=memory", Id::hash(&path.as_ref().to_path_buf())), 
                OpenFlags::SQLITE_OPEN_READ_WRITE |
                OpenFlags::SQLITE_OPEN_CREATE |
                OpenFlags::SQLITE_OPEN_URI
            )?
        } else {
            if let Some(parent) = path.as_ref().parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            Connection::open(path)?
        };
        conn.pragma_update(None, "locking_mode", "EXCLUSIVE")?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Exclusive)?;
        tx.execute("CREATE TABLE if not exists Cache(
            key TEXT NOT NULL PRIMARY KEY,
            value BLOB NOT NULL
        );", [])?;
        tx.commit()?;
        Ok(Cache(conn))
    }
    pub fn get<T: for<'a> Deserialize<'a>>(&self, key: &str) -> Result<Option<T>, Error> {
        Ok(self.0.query_row(
            &format!("SELECT value FROM Cache WHERE key='{key}'"),
            [], |r| Ok(postcard::from_bytes(&r.get::<_, Vec<u8>>(0)?).ok()),
        ).optional()?.flatten())
    }

    pub fn insert<T: Serialize>(&mut self, key: &str, value: &T) -> Result<(), Error> {
        self.0.execute(
            &format!("INSERT INTO Cache(key, value) VALUES ('{key}', ?1) ON CONFLICT DO UPDATE SET value=excluded.value;"),
            [postcard::to_allocvec(value).unwrap()],
        )?;
        Ok(())
    }
}
