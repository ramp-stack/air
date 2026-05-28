use serde::de::{Deserializer, Visitor, SeqAccess, MapAccess, DeserializeSeed, Unexpected, Error as _, VariantAccess, EnumAccess};
use serde::{forward_to_deserialize_any};

use super::{Substance, Error};

type Result<V> = std::result::Result<V, Error>;

impl<'de> Deserializer<'de> for Substance {
    type Error = Error;

    fn deserialize_any<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        match self {
            Substance::Null => visitor.visit_none(),
            Substance::Bytes(b) => visitor.visit_bytes(&b),
            Substance::String(s) => visitor.visit_str(&s),
            Substance::Integer(i) => visitor.visit_i64(i),
            Substance::Float(f) => visitor.visit_f64(f),
            Substance::Map(m) => visitor.visit_map(Map(m, None)),
            Substance::Seq(s) => visitor.visit_seq(Seq::new(s)),
            Substance::Named(_, i) => match *i {
                //Named(Map): Structure Or NewType(Map)
                Substance::Map(m) => visitor.visit_map(Map(m, None)),
                //Named(Seq): Tuple Struct Or NewType(Vec)
                Substance::Seq(s) => visitor.visit_seq(Seq::new(s)),
                //Named(Named): Enum
                Substance::Named(v, i) => visitor.visit_enum(Variant(v, *i)),
                //Named(Point): NewTypeStruct
                value => visitor.visit_newtype_struct(value),
            }
        }
    }

    fn deserialize_newtype_struct<V: Visitor<'de>>(self, _name: &'static str, visitor: V) -> Result<V::Value> {
        match self {
            Substance::Named(n, i) => match *i {
                Substance::Named(nn, _) => {Err(Error::invalid_type(Unexpected::Other("NewtypeStruct({name}))"), &format!("Enum: {n}::{nn}(...)").as_str()))},
                v => visitor.visit_newtype_struct(v)
            },
            _ => self.deserialize_any(visitor)
        }
    }

    fn deserialize_option<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        match self {
            Substance::Null => visitor.visit_none(),
            v => visitor.visit_some(v)
        }
    }

    forward_to_deserialize_any! {
        bool i8 i16 i32 i64 i128 u8 u16 u32 u64 u128 f32 f64 char str string
        bytes byte_buf unit unit_struct seq tuple
        tuple_struct map struct enum identifier ignored_any
    }
}

pub struct Map(im::OrdMap<String, Substance>, Option<Substance>);
impl<'de> MapAccess<'de> for Map {
    type Error = Error;

    fn next_key_seed<K: DeserializeSeed<'de>>(&mut self, seed: K) -> Result<Option<K::Value>> {
        self.0.keys().next().cloned().map(|k| {self.1 = self.0.remove(&k); seed.deserialize(Substance::String(k))}).transpose()
    }

    fn next_value_seed<V: DeserializeSeed<'de>>(&mut self, seed: V) -> Result<V::Value> {
        seed.deserialize(self.1.take().unwrap())
    }
}

pub struct Seq(im::Vector<Substance>);
impl Seq {
    pub fn new(objects: im::Vector<Substance>) -> Self {Seq(objects.into_iter().rev().collect())}
}
impl<'de> SeqAccess<'de> for Seq {
    type Error = Error;

    fn next_element_seed<T: DeserializeSeed<'de>>(&mut self, seed: T) -> Result<Option<T::Value>> {
        self.0.pop_back().map(|o| seed.deserialize(o)).transpose()
    }
}

impl<'de> VariantAccess<'de> for Substance {
    type Error = Error;

    fn unit_variant(self) -> Result<()> {
        match self {
            Substance::Null => Ok(()),
            Substance::Seq(_) => Err(Error::invalid_type(Unexpected::TupleVariant, &"unit variant")),
            Substance::Map(_) => Err(Error::invalid_type(Unexpected::StructVariant, &"unit variant")),
            _ => Err(Error::invalid_type(Unexpected::NewtypeVariant, &"unit variant"))
        }
    }

    fn newtype_variant_seed<T: DeserializeSeed<'de>>(self, seed: T) -> Result<T::Value> {
        match self {
          ////Enum(Null): Unit Variant
          //Substance::Null => Err(Error::invalid_type(Unexpected::UnitVariant, &"newtype variant")),
          ////Enum(Seq): Tuple Variant
          //Substance::Seq(_) => Err(Error::invalid_type(Unexpected::TupleVariant, &"newtype variant")),
          ////Enum(Map): Struct Variant
          //Substance::Map(_) => Err(Error::invalid_type(Unexpected::StructVariant, &"newtype variant")),
          ////Enum(Named(variant, i)): NewType Variant of an Enum Variant
            Substance::Named(n, i) => seed.deserialize(Substance::named("Enum", Substance::Named(n, i))),
            //Enum(Field): NewType Variant
            v => seed.deserialize(v)
        }
    }

    fn tuple_variant<V: Visitor<'de>>(self, _len: usize, visitor: V) -> Result<V::Value> {
        match self {
            Substance::Null => Err(Error::invalid_type(Unexpected::UnitVariant, &"tuple variant")),
            Substance::Seq(s) => visitor.visit_seq(Seq::new(s)),
            Substance::Map(_) => Err(Error::invalid_type(Unexpected::StructVariant, &"tuple variant")),
            _ => Err(Error::invalid_type(Unexpected::NewtypeVariant, &"tuple variant")),
        }
    }

    fn struct_variant<V: Visitor<'de>>(self, _fields: &'static [&'static str], visitor: V) -> Result<V::Value> {
        match self {
            Substance::Null => Err(Error::invalid_type(Unexpected::UnitVariant, &"struct variant")),
            Substance::Seq(_) => Err(Error::invalid_type(Unexpected::TupleVariant, &"struct variant")),
            Substance::Map(m) => visitor.visit_map(Map(m, None)),
            _ => Err(Error::invalid_type(Unexpected::NewtypeVariant, &"struct variant")),
        }
    }
}

pub struct Variant(String, Substance);
impl<'de> EnumAccess<'de> for Variant {
    type Error = Error;
    type Variant = Substance;

    fn variant_seed<V: DeserializeSeed<'de>>(self, seed: V) -> Result<(V::Value, Self::Variant)> {
        seed.deserialize(Substance::String(self.0)).map(|v| (v, self.1))
    }
}
