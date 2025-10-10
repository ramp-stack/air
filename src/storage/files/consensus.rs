use orange_name::{Name, secp256k1::{SecretKey, Signed as KeySigned}, Id, Secret};

use crate::server::{Error as PurserError, Command, Context, PurserRequest};
use crate::storage::{CreatePrivate, ReadPrivate, ReadPrivateHash};

use std::hash::{Hasher, Hash};
use std::time::Duration;
use std::path::PathBuf;

use crate::{DateTime, now};

use super::{File, Key, Error, FileCache, Serialized, RequestError};

use serde::{Serialize, Deserialize};

//  #[derive(Serialize, Deserialize)]
//  pub struct CreateFile(pub File<Serialized>);
//  impl Command<PurserRequest> for CreateFile {
//      type Output = Result<Option<DateTime>, RequestError>;

//      async fn run(self, mut ctx: Context) -> Self::Output {
//          let result = ctx.run(consensus::CreateFile(self.0.clone())).await?;
//          if result.is_none() {
//              ctx.get_mut_or_default::<FileCache>().await.cache(&self.0);
//          }
//          Ok(result)
//      }
//  }

#[derive(Serialize, Deserialize)]
pub struct ReadFile(pub PathBuf);
impl Command<PurserRequest> for ReadFile {
    type Output = Result<Option<Option<File<Serialized>>>, RequestError>;

    async fn run(self, mut ctx: Context) -> Self::Output {
        //1. Get parent from the cache
        //2. Get children key
        //3. Derive file_name from children_key and get key
        //4. Discover private_items from key until 
        let (key, servers, _) = ctx.get_mut_or_default::<FileCache>().await
            .get(&self.0).ok_or(Error::MissingFile(self.0))?.clone();
        Ok(consensus::ReadFile(key, servers).run(ctx).await?)
    }
}

//  #[derive(Serialize, Deserialize)]
//  pub struct ReadPointer(pub Pointer);
//  impl Command<PurserRequest> for ReadPointer {
//      type Output = Result<Option<Option<File<Serialized>>>, RequestError>;

//      async fn run(self, mut ctx: Context) -> Self::Output {
//          let Pointer{key, servers, file_id} = self.0;
//          let key = key.secret().ok_or(Error::MissingPerms("Secret Pointer".to_string()))?;
//          let file = ctx.run(consensus::ReadFile(key, servers)).await?;
//          if let Some(Some(file)) = file.as_ref() {ctx.get_mut_or_default::<FileCache>().await.cache(file);}
//          Ok(file.map(|file| file.filter(|file| Id::hash(file) == file_id)))
//      }
//  }

//  #[derive(Serialize, Deserialize)]
//  pub struct DiscoverFile(pub Id, pub usize);
//  impl Command<PurserRequest> for DiscoverFile {
//      type Output = Result<Option<Option<File<Serialized>>>, RequestError>;

//      async fn run(self, mut ctx: Context) -> Self::Output {
//          let children = ctx.get_mut_or_default::<FileCache>().await.get_children(&self.0)?.clone();
//          let key = children.get_key(self.1)?;
//          let file = ctx.run(consensus::ReadFile(key, children.1)).await?;
//          if let Some(Some(file)) = file.as_ref() {ctx.get_mut_or_default::<FileCache>().await.cache(file);}
//          Ok(file)
//      }
//  }
