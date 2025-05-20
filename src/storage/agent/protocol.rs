use super::Error;

use super::permissions::{
    ChannelOptions,
    PermissionOptions,
    PermissionSet,
};
use super::RecordPath;

use easy_secp256k1::{EasyHash, Hashable};

use serde::{Serialize, Deserialize};

//#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub type ProtocolId = [u8; 32];
//  impl AsRef<[u8; 32]> for ProtocolId {
//      fn as_ref(&self) -> &[u8; u32] {self.0.as_ref()}
//  }

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Hash)]
pub struct ChannelProtocol {
    pub child_protocols: Option<Vec<ProtocolId>>, //None for any child empty for no children
}
impl ChannelProtocol {
    pub fn new(child_protocols: Option<Vec<&Protocol>>) -> Self {
        ChannelProtocol{child_protocols: child_protocols.map(|cp| cp.into_iter().map(|p| p.id()).collect())}
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Hash)]
pub struct Protocol {
    name: String,//Name to make a destinction between identical protocol schemas
    //delete: bool,//Weather record can be deleted by anyone
    permissions: PermissionOptions,//Minimum Permissions required for each item
    max_length: usize,//Max size of the encrypted payload(There is zero padding at the moment
    channel: Option<ChannelProtocol>//None no channel, Some(Channel(Some(list))) channel items
                                        //restricted to protocols in list, Some(Channel(None)) allows
                                        //any protocol for channel items
}

impl Protocol {
    pub fn new(
        name: &str,
        permissions: PermissionOptions,
        max_length: usize,
        channel: Option<ChannelProtocol>
    ) -> Result<Self, Error> {
        if permissions.channel.is_some() != channel.is_some() {return Err(Error::ProtocolPermsMismatch);}
        Ok(Protocol{name: name.to_string(), permissions, max_length, channel})
    }

    pub fn id(&self) -> ProtocolId {*EasyHash::core_hash(self).as_ref()}
}

//      pub fn uuid(&self) -> Uuid {
//          Uuid::new_v5(&Uuid::NAMESPACE_OID, &self.hash_bytes())
//      }

//      pub fn trim_permission(&self, mut permission: PermissionSet) -> PermissionSet {
//          if !self.delete {permission.delete = None;}
//          if self.channel.is_none() {permission.channel = None;}
//          permission
//      }

//      pub fn subset_permission(
//          &self, permission: PermissionSet, permission_options: Option<&PermissionOptions>
//      ) -> Result<PermissionSet, Error> {
//          let options = permission_options.unwrap_or(&self.permissions);
//          let perms = self.trim_permission(permission).subset(options)?;
//          self.validate_permission(&perms)?;
//          Ok(perms)
//      }

//      pub fn validate_child(&self, child_protocol: &Uuid) -> Result<(), Error> {
//          if let Some(channel) = &self.channel {
//              if let Some(cps) = &channel.child_protocols {
//                  if !cps.contains(child_protocol) {
//                      return Err(Error::validation("Invalid Child Protocol"));
//                  }
//              }
//              Ok(())
//          } else {Err(Error::validation("No Channel For Protocol"))}
//      }

//      fn validate(&self) -> Result<(), Error> {
//          if self.channel.is_some() != self.permissions.channel.is_some() {
//              return Err(Error::validation("Channel Permission Without Channel Protocol"));
//          }
//          if !self.delete && self.permissions.can_delete {
//              return Err(Error::validation("Deletes Permission Without Deletes Enabled"));
//          }
//          Ok(())
//      }

//      pub fn validate_payload(&self, payload: &[u8]) -> Result<(), Error> {
//          if let Some(schema) = self.schema.as_ref() {
//              JSONSchema::compile(&serde_json::from_str(schema)?)
//              .map_err(|_| Error::validation("Invalid Schema"))?
//              .validate(&serde_json::from_slice(payload)?)
//              .map_err(|_| Error::validation("Invalid Payload"))
//          } else if !payload.is_empty() {
//              Err(Error::validation("Invalid Payload"))
//          } else {Ok(())}
//      }

//      pub fn validate_permission(&self, perms: &PermissionSet) -> Result<(), Error> {
//          let trimmed = self.trim_permission(perms.clone());
//          if trimmed != *perms {return Err(Error::validation("Protocol Restrictions Mismatch"));}
//          trimmed.subset(&self.permissions).or(Err(Error::validation("Insuffcient Permission")))?;
//          Ok(())
//      }
//  }

//  pub struct SystemProtocols{}
//  impl SystemProtocols {
//      pub fn root() -> Protocol {
//          Protocol::new(
//              "root",
//              false,
//              PermissionOptions::new(true, true, false, Some(
//                  ChannelPermissionOptions::new(true, true)
//              )),
//              None,
//              Some(ChannelProtocol::new(None))
//          ).unwrap()
//      }

//      pub fn dms_channel() -> Protocol {
//          Protocol::new(
//              "dms_channel",
//              true,
//              PermissionOptions::new(true, true, true, Some(
//                  ChannelPermissionOptions::new(true, true)
//              )),
//              None,
//              Some(ChannelProtocol::new(None))
//          ).unwrap()
//      }

//      pub fn agent_keys() -> Protocol {
//          Protocol::new(
//              "agent_keys",
//              true,
//              PermissionOptions::new(true, true, true, None),
//              Some(serde_json::to_string(&schema_for!(BTreeMap<RecordPath, PublicKey>)).unwrap()),
//              None
//          ).unwrap()
//      }

//      pub fn usize() -> Protocol {
//          Protocol::new(
//              "date_time",
//              true,
//              PermissionOptions::new(true, true, true, None),
//              Some(serde_json::to_string(&schema_for!(usize)).unwrap()),
//              None
//          ).unwrap()
//      }

//      pub fn perm_pointer() -> Protocol {
//          Protocol::new(
//              "perm_pointer",
//              false,
//              PermissionOptions::new(true, true, false, None),
//              Some(serde_json::to_string(&schema_for!(PermissionSet)).unwrap()),
//              None
//          ).unwrap()
//      }

//      pub fn pointer() -> Protocol {
//          Protocol::new(
//              "pointer",
//              true,
//              PermissionOptions::new(true, true, true, None),
//              Some(serde_json::to_string(&schema_for!(PermissionSet)).unwrap()),
//              None
//          ).unwrap()
//      }
//  }
