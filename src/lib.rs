pub mod server;
pub mod storage;

pub use orange_name;

pub type DateTime = chrono::DateTime::<chrono::Utc>;
pub fn now() -> DateTime {chrono::Utc::now()}
