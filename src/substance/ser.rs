use serde::ser::{SerializeSeq, SerializeTuple, SerializeTupleStruct, SerializeTupleVariant, SerializeMap, SerializeStruct, SerializeStructVariant};
use serde::Serialize;

use std::collections::BTreeMap;

use super::{Substance, Error};

type Result<V> = std::result::Result<V, Error>;

#[derive(Clone, Copy)]
pub struct Serializer;
impl serde::Serializer for Serializer {
    type Ok = Substance;
    type Error = Error;
    type SerializeSeq = Sequence;
    type SerializeTuple = Tuple;
    type SerializeTupleStruct = TupleStruct;
    type SerializeTupleVariant = TupleVariant;
    type SerializeMap = Map;
    type SerializeStruct = Struct;
    type SerializeStructVariant = StructVariant;

    fn serialize_bool(self, v: bool) -> Result<Substance> {Ok(Substance::Integer(v as i64))}
    fn serialize_i8(self, v: i8) -> Result<Substance> {Ok(Substance::Integer(v as i64))}
    fn serialize_i16(self, v: i16) -> Result<Substance> {Ok(Substance::Integer(v as i64))}
    fn serialize_i32(self, v: i32) -> Result<Substance> {Ok(Substance::Integer(v as i64))}
    fn serialize_i64(self, v: i64) -> Result<Substance> {Ok(Substance::Integer(v))}
    fn serialize_u8(self, v: u8) -> Result<Substance> {Ok(Substance::Integer(v as i64))}
    fn serialize_u16(self, v: u16) -> Result<Substance> {Ok(Substance::Integer(v as i64))}
    fn serialize_u32(self, v: u32) -> Result<Substance> {Ok(Substance::Integer(v as i64))}
    fn serialize_u64(self, v: u64) -> Result<Substance> {Ok(Substance::Integer(v as i64))}
    fn serialize_f32(self, v: f32) -> Result<Substance> {Ok(Substance::Float(v as f64))}
    fn serialize_f64(self, v: f64) -> Result<Substance> {Ok(Substance::Float(v))}
    fn serialize_char(self, v: char) -> Result<Substance> {Ok(Substance::String(v.to_string()))}
    fn serialize_str(self, v: &str) -> Result<Substance> {Ok(Substance::String(v.to_string()))}
    fn serialize_bytes(self, v: &[u8]) -> Result<Substance> {Ok(Substance::Bytes(v.to_vec()))}

    fn serialize_none(self) -> Result<Substance> {Ok(Substance::Null)}
    fn serialize_some<O: Serialize + ?Sized>(self, value: &O) -> Result<Substance> {
        value.serialize(self)
    }
    fn serialize_unit(self) -> Result<Substance> {Ok(Substance::Null)}

    fn serialize_unit_struct(self, name: &'static str) -> Result<Substance> {
        Ok(Substance::named(name, Substance::Null))
    }
    fn serialize_unit_variant(self, name: &'static str, _: u32, variant: &'static str) -> Result<Substance> {
        Ok(Substance::named(name, Substance::named(variant, Substance::Null)))
    }

    fn serialize_newtype_struct<T: Serialize + ?Sized>(self, name: &'static str, value: &T) -> Result<Substance> {
        Ok(Substance::named(name, value.serialize(self)?.unname()))
    }
    fn serialize_newtype_variant<T: Serialize + ?Sized>(
        self, name: &'static str, _: u32, variant: &'static str, value: &T
    ) -> Result<Substance> {
        Ok(Substance::named(name, Substance::named(variant, value.serialize(self)?.unname())))
    }

    fn serialize_struct(self, name: &'static str, _: usize) -> Result<Struct> {
        Ok(Struct(name.to_string(), BTreeMap::new()))
    }
    fn serialize_struct_variant(self, name: &'static str, _: u32, variant: &'static str, _: usize) -> Result<StructVariant> {
        Ok(StructVariant(name.to_string(), variant.to_string(), BTreeMap::new()))
    }

    fn serialize_tuple_struct(self, name: &'static str, _: usize) -> Result<TupleStruct> {
        println!("tuple_struct");
        Ok(TupleStruct(name.to_string(), Vec::new()))
    }
    fn serialize_tuple_variant(self, name: &'static str, _: u32, variant: &'static str, _: usize) -> Result<TupleVariant> {
        Ok(TupleVariant(name.to_string(), variant.to_string(), Vec::new()))
    }

    fn serialize_tuple(self, _: usize) -> Result<Tuple> {Ok(Tuple(Vec::new()))}
    fn serialize_seq(self, _: Option<usize>) -> Result<Sequence> {Ok(Sequence(Vec::new()))}
    fn serialize_map(self, _: Option<usize>) -> Result<Map> {Ok(Map(None, BTreeMap::new()))}
}

pub struct Map(Option<Substance>, BTreeMap<String, Substance>);
impl SerializeMap for Map {
    type Ok = Substance;
    type Error = Error;

    fn serialize_key<T: Serialize + ?Sized>(&mut self, key: &T) -> Result<()> {
        self.0 = Some(key.serialize(Serializer)?);
        Ok(())
    }
    fn serialize_value<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<()> {
        self.1.insert(self.0.take().unwrap().to_string(), value.serialize(Serializer)?);
        Ok(())
    }
    fn end(self) -> Result<Substance> {
        Ok(Substance::Map(self.1.into()))
    }
}

pub struct Sequence(Vec<Substance>);
impl SerializeSeq for Sequence {
    type Ok = Substance;
    type Error = Error;

    fn serialize_element<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<()> {
        self.0.push(value.serialize(Serializer)?);
        Ok(())
    }
    fn end(self) -> Result<Substance> {
        Ok(Substance::Seq(self.0.into()))
    }
}

pub struct Tuple(Vec<Substance>);
impl SerializeTuple for Tuple {
    type Ok = Substance;
    type Error = Error;

    fn serialize_element<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<()> {
        self.0.push(value.serialize(Serializer)?);
        Ok(())
    }
    fn end(self) -> Result<Substance> {
        Ok(Substance::Seq(self.0.into()))
    }
}

pub struct TupleStruct(String, Vec<Substance>);
impl SerializeTupleStruct for TupleStruct {
    type Ok = Substance;
    type Error = Error;

    fn serialize_field<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<()> {
        self.1.push(value.serialize(Serializer)?);
        Ok(())
    }
    fn end(self) -> Result<Substance> {
        Ok(Substance::named(&self.0, Substance::Seq(self.1.into())))
    }
}

pub struct TupleVariant(String, String, Vec<Substance>);
impl SerializeTupleVariant for TupleVariant {
    type Ok = Substance; 
    type Error = Error;

    fn serialize_field<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<()> {
        self.2.push(value.serialize(Serializer)?);
        Ok(())
    }
    fn end(self) -> Result<Substance> {
        Ok(Substance::named(&self.0, Substance::named(&self.1, Substance::Seq(self.2.into()))))
    }
}

pub struct Struct(String, BTreeMap<String, Substance>);
impl SerializeStruct for Struct {
    type Ok = Substance;
    type Error = Error;

    fn serialize_field<T: Serialize + ?Sized>(&mut self, key: &'static str, value: &T) -> Result<()> {
        self.1.insert(key.to_string(), value.serialize(Serializer)?);
        Ok(())
    }
    fn end(self) -> Result<Substance> {Ok(Substance::named(&self.0, Substance::Map(self.1.into())))}
}

pub struct StructVariant(String, String, BTreeMap<String, Substance>);
impl SerializeStructVariant for StructVariant {
    type Ok = Substance;
    type Error = Error;

    fn serialize_field<T: Serialize + ?Sized>(&mut self, key: &'static str, value: &T) -> Result<()> {
        self.2.insert(key.to_string(), value.serialize(Serializer)?);
        Ok(())
    }
    fn end(self) -> Result<Substance> {
        Ok(Substance::named(&self.0, Substance::named(&self.1, Substance::Map(self.2.into()))))
    }
}
