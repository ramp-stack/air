pub mod orange_name;
pub mod server;
pub mod storage;

use serde::{Serialize, Deserialize};
use easy_secp256k1::Hashable;

pub type DateTime = chrono::DateTime::<chrono::Utc>;
pub fn now() -> DateTime {chrono::Utc::now()}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Copy)]
pub struct Id([u8; 32]);
impl AsRef<[u8]> for Id {fn as_ref(&self) -> &[u8] {&self.0}}
impl std::ops::Deref for Id {type Target = [u8; 32]; fn deref(&self) -> &Self::Target {&self.0}}
impl std::ops::DerefMut for Id {fn deref_mut(&mut self) -> &mut Self::Target {&mut self.0}}
impl From<[u8; 32]> for Id {fn from(id: [u8; 32]) -> Self {Id(id)}}
impl Id {
    pub const MAX: Id = Id([u8::MAX; 32]);
    pub const MIN: Id = Id([u8::MIN; 32]);
    pub fn hash<H: std::hash::Hash>(h: &H) -> Self {Id(*easy_secp256k1::EasyHash::core_hash(h).as_ref())}
    pub fn random() -> Self {Id(secp256k1::rand::random())}
}
impl std::fmt::Display for Id {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}
impl std::str::FromStr for Id {
    type Err = hex::FromHexError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Id(hex::decode(s)?.try_into().map_err(|_| hex::FromHexError::InvalidStringLength)?))
    }
}
