use easy_secp256k1::{EasySecretKey};
use secp256k1::{SecretKey, PublicKey};

use serde::{Serialize, Deserialize};
use std::cmp::Ordering;
use std::hash::{Hash, Hasher};

use super::{Error, RecordPath};

mod key;
pub use key::Key;

#[derive(Serialize, Deserialize, Default, Clone, Debug, PartialEq, Eq, Hash)]
pub struct ChannelOptions {
    pub can_create: bool,
    pub can_read: bool,
}

impl ChannelOptions {
    pub const fn new(can_create: bool, can_read: bool) -> Self {
        ChannelOptions{can_create, can_read}
    }
}

#[derive(Serialize, Deserialize, Default, Clone, Debug, PartialEq, Eq, Hash)]
pub struct PermissionOptions {
    pub can_create: bool,
    pub can_read: bool,
    pub can_delete: Option<bool>,
    pub channel: Option<ChannelOptions>//None no channel
}

impl PermissionOptions {
    pub const fn new(can_create: bool, can_read: bool, can_delete: Option<bool>, channel: Option<ChannelOptions>) -> Self {
        PermissionOptions{can_create, can_read, can_delete, channel}
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Hash)]
pub struct ChannelPermissionSet {
    pub discover: Key,
    pub create: Key,
    pub read: Key,
}

impl ChannelPermissionSet {
    pub const fn new(discover: Key, create: Key, read: Key) -> Self {
        ChannelPermissionSet{discover, create, read}
    }

    pub fn min(self, options: &ChannelOptions) -> Result<Self, Error> {
        Ok(ChannelPermissionSet{
            discover: self.discover.min(options.can_create || options.can_read, "Discover Child")?,
            create: self.create.min(options.can_create, "Discover Child")?,
            read: self.read.min(options.can_read, "Read Child")?,
        })
    }

    pub fn max(self, other: Self) -> Result<Self, Error> {
        Ok(ChannelPermissionSet{
            discover: self.discover.max(other.discover)?,
            create: self.create.max(other.create)?,
            read: self.read.max(other.read)?,
        })
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct PermissionSet {
    //pub path: RecordPath,
    pub discover: SecretKey,
    pub create: Key,
    pub read: Key,
    pub delete: Option<Key>,
    pub channel: Option<ChannelPermissionSet>
}

impl PermissionSet {
    pub fn new(
        //path: RecordPath,
        discover: SecretKey,
        create: Key,
        read: Key,
        delete: Option<Key>,
        channel: Option<ChannelPermissionSet>
    ) -> Self {
        PermissionSet{discover, create, read, delete, channel}
    }

  //pub fn discover(&self) -> SecretKey {
  //    self.discover.clone()
  //}

  //pub fn create(&self) -> Result<SecretKey, Error> {
  //    self.create.secret_key().ok_or(Error::invalid_auth("Create"))
  //}

  //pub fn read(&self) -> Result<SecretKey, Error> {
  //    self.read.secret_key().ok_or(Error::invalid_auth("Read"))
  //}

  //pub fn delete(&self) -> Result<SecretKey, Error> {
  //    self.delete.as_ref()
  //    .ok_or(Error::invalid_auth("Protocol Does Not Support Delete"))?
  //    .secret_key().ok_or(Error::invalid_auth("Delete"))
  //}

  //pub fn channel(&self) -> Result<&ChannelPermissionSet, Error> {
  //    self.channel.as_ref().ok_or(Error::invalid_auth("Channel"))
  //}

  //pub fn discover_child(&self) -> Result<SecretKey, Error> {
  //    self.channel()?.discover.secret_key()
  //    .ok_or(Error::invalid_auth("Discover Child"))
  //}

  //pub fn create_child(&self) -> Result<SecretKey, Error> {
  //    self.channel()?.create.secret_key()
  //    .ok_or(Error::invalid_auth("Create Child"))
  //}

  //pub fn read_child(&self) -> Result<SecretKey, Error> {
  //    self.channel()?.read.secret_key()
  //    .ok_or(Error::invalid_auth("Create Child"))
  //}

  //pub fn pointer(&self, index: usize) -> Result<Self, Error> {
  //    Ok(PermissionSet::new(
  //        RecordPath::new(&[]),
  //        self.discover_child()?.derive_usize(index)?,
  //        self.channel()?.create.clone(),
  //        self.channel()?.read.clone(),
  //        None, None
  //    ))
  //}

    pub fn min(self, options: &PermissionOptions) -> Result<Self, Error> {
        Ok(PermissionSet{
            discover: self.discover,
            create: self.create.min(options.can_create, "Create")?,
            read: self.read.min(options.can_read, "Read")?,
            delete: options.can_delete.as_ref().map(|can_delete| self.delete.ok_or(Error::MissingPerms("Delete".to_string()))?.min(*can_delete, "Delete")).transpose()?,
            channel: options.channel.as_ref().map(|channel| self.channel.ok_or(Error::MissingPerms("Channel".to_string()))?.min(channel)).transpose()?,
        })
    }

    //If one set contains delete or channel and the other does not remove delete and channel keys
    pub fn max(self, other: Self) -> Result<Self, Error> {
        Ok(PermissionSet{
            discover: self.discover,
            create: self.create.max(other.create)?,
            read: self.read.max(other.read)?,
            delete: self.delete.filter(|_| other.delete.is_none()).map(|d| d.max(other.delete.unwrap())).transpose()?,
            channel: self.channel.filter(|_| other.channel.is_none()).map(|c| c.max(other.channel.unwrap())).transpose()?
        })
    }
}

impl Hash for PermissionSet {
    fn hash<H: Hasher>(&self, state: &mut H) {
        state.write(&self.discover.secret_bytes());
        self.create.hash(state);
        self.read.hash(state);
        self.delete.hash(state);
        self.channel.hash(state);
    }
}
