use std::path::Path;
use orange_name::Id;

pub fn path_to_ids<P: AsRef<Path>>(path: P) -> Vec<Id> {
    path.as_ref().components().map(|c| Id::hash(&c.as_os_str().to_string_lossy().to_string())).collect::<Vec<_>>()
}
