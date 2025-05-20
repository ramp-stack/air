use easy_secp256k1::EasySecretKey;
use secp256k1::{SecretKey, PublicKey};
use serde::{Serialize, Deserialize};
use std::hash::{Hasher, Hash};
use super::ValidationError;

#[derive(Serialize, Deserialize, Default, Clone, Debug, PartialEq, Eq, Hash)]
pub struct AuthorOptions {
    pub can_create: bool,
    pub can_read: bool,
    pub can_delete: Option<bool>
}

impl AuthorOptions {
    pub const fn new(can_create: bool, can_read: bool, can_delete: Option<bool>) -> Self {
        AuthorOptions{can_create, can_read, can_delete}
    }
}

#[derive(Serialize, Deserialize, Default, Clone, Debug, PartialEq, Eq, Hash)]
pub struct ChannelOptions {
    pub can_create: bool,
    pub can_read: bool,
    pub can_delete: bool
}

impl ChannelOptions {
    pub const fn new(can_create: bool, can_read: bool, can_delete: bool) -> Self {
        ChannelOptions{can_create, can_read, can_delete}
    }
}

#[derive(Serialize, Deserialize, Default, Clone, Debug, PartialEq, Eq, Hash)]
pub struct PermissionOptions {
    pub delete: bool,
    pub author: Option<AuthorOptions>,//Actions the author can take
    pub channel: Option<ChannelOptions>//None no channel
}

impl PermissionOptions {
    pub const fn new(delete: bool, author: Option<AuthorOptions>, channel: Option<ChannelOptions>) -> Self {
        PermissionOptions{delete, author, channel}
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct AuthorSet {
    pub(crate) create: Key,
    pub(crate) read: Key,
}

impl AuthorSet {
    pub fn set(self, options: &AuthorOptions) -> Result<Self, ValidationError> {
        Ok(AuthorSet{
            create: self.create.set(options.can_create, "Create")?,
            read: self.read.set(options.can_read, "Read")?,
            delete: options.can_delete.as_ref().map(|can_delete| self.delete.ok_or(
                ValidationError::MissingAction("Delete".to_string())
            )?.set(*can_delete, "Delete")).transpose()?,
        })
    }

    pub fn trim(self, options: &AuthorOptions) -> Result<Self, ValidationError> {
        Ok(AuthorSet{
            create: self.create,
            read: self.read,
            delete: options.can_delete.as_ref().map(|_| self.delete.ok_or(
                ValidationError::MissingAction("Delete".to_string())
            )).transpose()?,
        })
    }

    pub(crate) fn validate(&self, options: &AuthorOptions) -> Result<(), ValidationError> {
        let e = |p: &str| Err(ValidationError::MissingPerms(p.to_string()));
        if options.can_create && matches!(self.create, Key::Public(_)) {return e("Create");}
        if options.can_read && matches!(self.read, Key::Public(_)) {return e("Read");}
        if options.can_delete.is_some() != self.delete.is_some() {return Err(ValidationError::MissingAction("Delete".to_string()));}
        if options.can_delete.map(|cd| cd && matches!(self.delete, Some(Key::Public(_)))).unwrap_or_default() {return e("Delete");}
        Ok(())
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct ChannelSet {
    pub(crate) discover: Key,
    pub(crate) create: Key,
    pub(crate) read: Key,
    pub(crate) delete: Key,
}

impl ChannelSet {
    pub fn set(self, options: &ChannelOptions) -> Result<Self, ValidationError> {
        Ok(ChannelSet{
            discover: self.discover.set(options.can_create || options.can_read || options.can_delete, "Discover Child")?,
            create: self.create.set(options.can_create, "Discover Child")?,
            read: self.read.set(options.can_read, "Read Child")?,
            delete: self.delete.set(options.can_delete, "Delete Child")?,
        })
    }

    pub fn validate(&self, options: &ChannelOptions) -> Result<(), ValidationError> {
        let e = |p: &str| Err(ValidationError::MissingPerms(p.to_string()));
        if (options.can_create || options.can_read || options.can_delete) && matches!(self.discover, Key::Public(_)) {return e("Discover Child");}
        if options.can_create && matches!(self.create, Key::Public(_)) {return e("Create Child");}
        if options.can_read && matches!(self.read, Key::Public(_)) {return e("Read, Child");}
        if options.can_delete && matches!(self.delete, Key::Public(_)) {return e("Delete Child");}
        Ok(())
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Pointer {
    pub(crate) discover: SecretKey,
    pub(crate) create: Key,
    pub(crate) read: Key,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct PermissionSet {
    pub(crate) discover: SecretKey,
    pub(crate) author: Option<AuthorSet>,
    pub(crate) channel: Option<ChannelSet>
}

impl PermissionSet {
    pub fn new(key: &SecretKey) -> Result<Self, ValidationError> {
        Ok(PermissionSet{
            discover: key.easy_derive(&[0])?,
            author: Some(AuthorSet{
                create: Key::Secret(key.easy_derive(&[1])?),
                read: Key::Secret(key.easy_derive(&[2])?),
                delete: Some(Key::Secret(key.easy_derive(&[3])?)),
            }),
            channel: Some(ChannelSet{
                discover: Key::Secret(key.easy_derive(&[4])?),
                create: Key::Secret(key.easy_derive(&[5])?),
                read: Key::Secret(key.easy_derive(&[6])?),
                delete: Key::Secret(key.easy_derive(&[7])?),
            })
        })
    }

    pub fn pointer(&self, index: u32) -> Result<Pointer, ValidationError> {
        let channel = self.channel.as_ref().ok_or(ValidationError::MissingPerms("Channel".to_string()))?;
        Ok(Pointer{
            discover: channel.discover.secret().ok_or(ValidationError::MissingPerms("Discover Child".to_string()))?
                .easy_derive(&[(u8::MAX as u32 * 2)+index])?,
            create: channel.create.clone(),
            read: channel.read.clone()
        })
    }

////pub fn validate_child(&self, other: &Self) -> Result<(), ValidationError> {
////    let channel = self.channel.as_ref().ok_or(ValidationError::MissingPerms("Channel".to_string()))?;
////    if other.create.public() != channel.create.public() {return Err(ValidationError::DifferentKeys);}
////    if other.read.public() != channel.read.public() {return Err(ValidationError::DifferentKeys);}
////    Ok(())
////}

    pub fn set(self, options: &PermissionOptions) -> Result<Self, ValidationError> {
        Ok(PermissionSet{
            discover: self.discover,
            author: options.author.as_ref().map(|author|
                self.author.ok_or(ValidationError::MissingAction("Author".to_string()))?.set(author)
            ).transpose()?,
            channel: options.channel.as_ref().map(|channel|
                self.channel.ok_or(ValidationError::MissingAction("Channel".to_string()))?.set(channel)
            ).transpose()?,
        })
    }

    pub fn trim(self, options: &PermissionOptions) -> Result<Self, ValidationError> {
        Ok(PermissionSet{
            discover: self.discover,
            author: options.author.as_ref().map(|author| self.author.ok_or(
                ValidationError::MissingAction("Author".to_string())
            )?.trim(author)).transpose()?,
            channel: options.channel.as_ref().map(|_| self.channel.ok_or(
                ValidationError::MissingAction("Channel".to_string())
            )).transpose()?,
        })
    }

//  ///Max keys min actions
//  pub fn max(&self, other: Self) -> Result<Self, ValidationError> {
//      Ok(PermissionSet{
//          create: self.create.max(other.create)?,
//          read: self.read.max(other.read)?,
//          delete: self.delete.as_ref().filter(|_| other.delete.is_none()).map(|d| d.max(other.delete.unwrap())).transpose()?,
//          channel: self.channel.as_ref().filter(|_| other.channel.is_none()).map(|c| c.max(other.channel.unwrap())).transpose()?
//      })
//  }

    pub(crate) fn validate(&self, options: &PermissionOptions) -> Result<(), ValidationError> {
        if options.author.is_some() != self.author.is_some() {return Err(ValidationError::MissingAction("Author".to_string()));}
        self.author.as_ref().map(|c| c.validate(options.author.as_ref().unwrap())).transpose()?;
        if options.channel.is_some() != self.channel.is_some() {return Err(ValidationError::MissingAction("Channel".to_string()));}
        self.channel.as_ref().map(|c| c.validate(options.channel.as_ref().unwrap())).transpose()?;
        Ok(())
    }

//  ///Validate that self has the same keys as superset which is allowed to contain more actions
//  ///than self. Error if self contains more actions than superset
//  pub(crate) fn validate_superset(&self, superset: &Self) -> Result<(), ValidationError> {
//      let am = |a: &str| ValidationError::ActionMismatch(a.to_string());
//      let dk = Err(ValidationError::DifferentKeys);
//      if self.create.public() != superset.create.public() {return dk;}
//      if self.read.public() != superset.read.public() {return dk;}
//      if self.delete.as_ref().map(|d| Ok::<_, ValidationError>(
//              d.public() != superset.delete.as_ref().ok_or(am("Delete"))?.public()
//      )).transpose()?.unwrap_or_default() {return dk;}
//      self.channel.as_ref().map(|c| c.validate_other(superset.channel.as_ref().ok_or(am("Channel"))?)).transpose()?;
//      Ok(())
//  }
}

impl Hash for PermissionSet {
    fn hash<H: Hasher>(&self, state: &mut H) {
        state.write(&self.discover.secret_bytes());
        self.author.hash(state);
        self.channel.hash(state);
    }
}

//  impl ChannelPermissionSet {
//      pub fn set(self, options: &ChannelOptions) -> Result<Self, ValidationError> {
//          Ok(ChannelPermissionSet{
//              discover: self.discover.set(options.can_create || options.can_read || options.can_delete, "Discover Child")?,
//              create: self.create.set(options.can_create, "Discover Child")?,
//              read: self.read.set(options.can_read, "Read Child")?,
//              delete: self.delete.set(options.can_delete, "Delete Child")?,
//          })
//      }

//      pub fn max(&self, other: Self) -> Result<Self, ValidationError> {
//          Ok(ChannelPermissionSet{
//              discover: self.discover.max(other.discover)?,
//              create: self.create.max(other.create)?,
//              read: self.read.max(other.read)?,
//              delete: self.delete.max(other.delete)?,
//          })
//      }

//      pub fn validate_minimum(&self, options: &ChannelOptions) -> Result<(), ValidationError> {
//          let e = |p: &str| Err(ValidationError::MissingPerms(p.to_string()));
//          if (options.can_create || options.can_read || options.can_delete) && matches!(self.discover, Key::Public(_)) {return e("Discover");}
//          if options.can_create && matches!(self.create, Key::Public(_)) {return e("Create");}
//          if options.can_read && matches!(self.read, Key::Public(_)) {return e("Read");}
//          if options.can_delete && matches!(self.delete, Key::Public(_)) {return e("Delete");}
//          Ok(())
//      }

//      pub fn validate_other(&self, other: &Self) -> Result<(), ValidationError> {
//          let dk = Err(ValidationError::DifferentKeys);
//          if self.create.public() != other.create.public() {return dk;}
//          if self.read.public() != other.read.public() {return dk;}
//          Ok(())
//      }

//    //pub fn create(&self, index: u32) -> Result<PermissionSet, ValidationError> {
//    //    Ok(PermissionSet{
//    //        discover: self.discover.secret().ok_or(
//    //            ValidationError::MissingPerms("DiscoverChild".to_string())
//    //        )?.easy_derive(&[index]).map_err(|_| ValidationError::NotHardenedIndex(index))?,
//    //        create: Key::Secret(self.create.secret().ok_or(ValidationError::MissingPerms("CreateChild".to_string()))?),
//    //        read: self.read.clone(),
//    //        delete: None,
//    //        channel: None
//    //    })
//    //}

//    //pub fn read(&self, index: u32) -> Result<PermissionSet, ValidationError> {
//    //    Ok(PermissionSet{
//    //        discover: self.discover.secret().ok_or(
//    //            ValidationError::MissingPerms("DiscoverChild".to_string())
//    //        )?.easy_derive(&[index]).map_err(|_| ValidationError::NotHardenedIndex(index))?,
//    //        create: self.create.clone(),
//    //        read: Key::Secret(self.read.secret().ok_or(ValidationError::MissingPerms("ReadChild".to_string()))?),
//    //        delete: None,
//    //        channel: None
//    //    })
//    //}
//  }
//
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub(crate) enum Key {
    Secret(SecretKey),
    Public(PublicKey),
}
impl Hash for Key {
    fn hash<H: Hasher>(&self, state: &mut H) {match self {
        Key::Secret(key) => state.write(&key.secret_bytes()),
        Key::Public(key) => key.hash(state)
    }}
}
impl Key {
    pub fn public(&self) -> PublicKey {
        match self {Key::Secret(key) => key.easy_public_key(), Key::Public(key) => *key}
    }
    pub fn secret(&self) -> Option<SecretKey> {
        match self {Key::Secret(key) => Some(*key), Key::Public(_) => None}
    }

    pub fn set(self, secret: bool, error: &str) -> Result<Self, ValidationError> {
        match secret && matches!(self, Key::Public(_)) {
            true => Err(ValidationError::MissingPerms(error.to_string())),
            false => Ok(match secret {
                true => self,
                false => Key::Public(self.public())
            })
        }
    }

    pub fn max(&self, other: Self) -> Result<Self, ValidationError> {
        match self.public() != other.public() {
            true => Err(ValidationError::DifferentKeys), 
            false => Ok(match &self {
                Key::Secret(_) => self.clone(),
                Key::Public(_) => other
            })
        }
    }
}


