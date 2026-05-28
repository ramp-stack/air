use serde::{Serialize, Deserialize};

use std::hash::{DefaultHasher, Hasher, Hash};
use std::path::Path;
use std::cmp::Ordering;

mod ser;
pub use ser::Serializer;
mod de;

mod beaker;
pub use beaker::{Beaker, Offset, Logger};

pub trait PathedError: std::error::Error {
    ///The path that the error occured at while traversing a substance or beaker
    fn path(&self) -> &Path;
}

#[derive(Debug)]
pub enum Error {
    Serialization(String),
    Deserialization(String),
}
impl std::error::Error for Error {}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {write!(f, "{:?}", self)}
}
impl serde::ser::Error for Error {
    fn custom<T: std::fmt::Display>(msg: T) -> Error {Error::Serialization(msg.to_string())}
}
impl serde::de::Error for Error {
    fn custom<T: std::fmt::Display>(msg: T) -> Self {Error::Deserialization(msg.to_string())}
}

pub fn into<S: Serialize>(s: &S) -> Result<Substance, Error> {s.serialize(Serializer)}
pub fn from<D: for<'a> Deserialize<'a>>(s: Substance) -> Result<D, Error> {D::deserialize(s)}

#[derive(Serialize, Deserialize, Default, Clone)]
pub enum Substance {
    #[default]
    Null,

    Integer(i64),
    Float(f64),
    Bytes(Vec<u8>),
    String(String),

    Seq(im::Vector<Self>),
    Map(im::OrdMap<String, Self>),
    Named(String, Box<Self>),
}

impl Substance {
    pub fn map() -> Self {Self::Map(im::OrdMap::default())}

    pub fn as_bytes(&self) -> Option<&[u8]> {if let Self::Bytes(r) = self {Some(r)} else {None}}
    pub fn as_str(&self) -> Option<&str> {if let Self::String(r) = self {Some(r.as_str())} else {None}}
    pub fn as_string(&self) -> Option<&String> {if let Self::String(r) = self {Some(r)} else {None}}
    pub fn as_int(&self) -> Option<i64> {if let Self::Integer(r) = self {Some(*r)} else {None}}
    pub fn as_float(&self) -> Option<f64> {if let Self::Float(r) = self {Some(*r)} else {None}}
    pub fn as_map(&self) -> Option<&im::OrdMap<String, Self>> {if let Self::Map(r) = self {Some(r)} else {None}}
    pub fn as_seq(&self) -> Option<&im::Vector<Self>> {if let Self::Seq(r) = self {Some(r)} else {None}}

    pub fn discriminant(&self) -> u8 {match self {
        Self::Null => 0,
        Self::Integer(_) => 1,
        Self::Float(_) => 2,
        Self::Bytes(_) => 3,
        Self::String(_) => 4,
        Self::Seq(_) => 5,
        Self::Map(_) => 6,
        Self::Named(_, _) => 7,
    }}

    pub fn keys(&self) -> Option<Vec<String>> {
        if let Self::Map(m) = self {Some(m.keys().cloned().collect())} else {None}
    }

    pub fn get(&self, k: &str) -> Option<&Self> {match self {
        Self::Named(_, i) => i.get(k),
        Self::Map(map) => map.get(k),
        Self::Seq(seq) => k.parse::<usize>().ok().and_then(|i| seq.get(i)),
        _ => None
    }}

    pub fn get_mut(&mut self, k: &str) -> Option<&mut Self> {match self {
        Self::Named(_, i) => i.get_mut(k),
        Self::Map(map) => map.get_mut(k),
        Self::Seq(seq) => k.parse::<usize>().ok().and_then(|i| seq.get_mut(i)),
        _ => None
    }}

    pub fn remove(self, k: &str) -> Option<Self> {match self {
        Self::Named(_, i) => i.remove(k),
        Self::Map(mut map) => map.remove(k),
        Self::Seq(mut seq) => k.parse::<usize>().ok().and_then(|i| (i < seq.len()).then(|| seq.remove(i))),
        _ => None
    }}

    pub fn named(name: &str, value: Self) -> Self {
        Substance::Named(name.to_string(), Box::new(value))
    }

    pub fn unname(self) -> Self {match self {
        Self::Named(_, s) => *s,
        other => other
    }}
}

impl Eq for Substance {}
impl PartialEq for Substance {fn eq(&self, other: &Self) -> bool {self.cmp(other) == Ordering::Equal}}
impl PartialOrd for Substance {fn partial_cmp(&self, other: &Self) -> Option<Ordering> {Some(self.cmp(other))}}
impl Ord for Substance {
    fn cmp(&self, other: &Self) -> Ordering {
        match (self, other) {
            (Substance::Map(a), Substance::Map(b)) => a.cmp(b),
            (Substance::Seq(a), Substance::Seq(b)) => a.cmp(b),
            (Substance::Named(an, a), Substance::Named(bn, b)) => (an, a).cmp(&(bn, b)),
            (a, b) => {
                let sf = self.as_float().or(self.as_int().map(|i| i as f64));
                let of = other.as_float().or(other.as_int().map(|i| i as f64));
                let sb = self.as_bytes().or(self.as_string().map(|s| s.as_bytes()));
                let ob = other.as_bytes().or(other.as_string().map(|s| s.as_bytes()));
                match ((sf, sb), (of, ob)) {
                    ((Some(a), _), (Some(b), _)) => a.total_cmp(&b),
                    ((_, Some(a)), (_, Some(b))) => a.cmp(b),
                    ((Some(_), _), (_, Some(_))) => Ordering::Less,
                    ((_, Some(_)), (Some(_), _)) => Ordering::Greater,
                    _ => a.discriminant().cmp(&b.discriminant())
                }
            }
        }
    }
}

impl Hash for Substance {
    fn hash<H: Hasher>(&self, state: &mut H) {match self {
        Self::Null => 0.hash(state),
        Self::Bytes(b) => {1.hash(state); b.hash(state)},
        Self::String(s) => {2.hash(state); s.hash(state)},
        Self::Integer(i) => {3.hash(state); i.hash(state)},
        Self::Float(f) => {4.hash(state); f.to_bits().hash(state)},
        Self::Map(map) => {5.hash(state); map.hash(state)},
        Self::Seq(seq) => {6.hash(state); seq.hash(state)},
        Self::Named(name, s) => {7.hash(state); name.hash(state); s.hash(state)},
    }}
}

impl std::fmt::Display for Substance {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Null => write!(f, "Null"),
            Self::String(s) => write!(f, "{}", s),
            Self::Bytes(b) => write!(f, "{}", std::str::from_utf8(b).map(|s| s.to_string()).unwrap_or_else(|_| format!("{:02x?}", b))),
            Self::Integer(i) => write!(f, "{}", i),
            Self::Float(r) => write!(f, "{}", r),
            other => {
                let mut hasher = DefaultHasher::new();
                other.hash(&mut hasher);
                write!(f, "{}", hasher.finish())
            },
        }
    }
}

impl std::fmt::Debug for Substance {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Null => write!(f, "Null"),
            Self::String(s) => write!(f, "{:?}", s),
            Self::Bytes(b) => write!(f, "{:?}..{}..{:?}", &b[..4], b.len()-8, &b[b.len()-4..]),
            Self::Integer(i) => write!(f, "{:?}", i),
            Self::Float(r) => write!(f, "{:?}", r),
            Self::Seq(s) => f.debug_list().entries(s).finish(),
            Self::Map(c) => {
                if c.is_empty() {
                    f.debug_map().entries(c).finish()
                } else {
                    let mut s = f.debug_struct("");
                    c.iter().for_each(|(n, v)| {s.field(n, v);});
                    s.finish()
                }
            },
            Self::Named(name, i) => match &**i {
                Self::Map(c) => {
                    let mut s = f.debug_struct(name);
                    c.iter().for_each(|(n, v)| {s.field(n, v);});
                    s.finish()
                },
                o if matches!(o, Self::Named(_, _)) => {write!(f, "{name}::")?; o.fmt(f)},
                p => write!(f, "{name}({p:?})") 
            }
        }
    }
}
