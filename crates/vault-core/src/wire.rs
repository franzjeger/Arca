//! The positional binary encoding of the vault container's body.
//!
//! Byte for byte what bincode 1 wrote with fixed-width integers, the
//! configuration every Arca vault has been written with (`DefaultOptions`,
//! `with_fixint_encoding`, `reject_trailing_bytes`), so every file ever
//! written still reads. Arca owns it here because bincode is unmaintained
//! (RUSTSEC-2025-0141), and a password manager's file format must not hang on
//! a crate nobody looks after. Everything is little-endian:
//!
//! | value                              | bytes                                 |
//! |------------------------------------|---------------------------------------|
//! | `bool`                             | 1 byte: 0 or 1                        |
//! | `u8`–`u64`, `i8`–`i64`             | 1, 2, 4 or 8 bytes                    |
//! | `f32`, `f64`                       | 4 or 8 bytes, IEEE 754                |
//! | string, bytes, sequence, map       | `u64` count, then the elements        |
//! | fixed-size array, tuple            | the elements, no count                |
//! | `Option`                           | 0 for `None`; 1, then the value       |
//! | struct                             | its fields in declaration order       |
//! | enum                               | `u32` variant index, then its fields  |
//! | unit, unit struct                  | nothing                               |
//!
//! A decode must use the input exactly: trailing bytes are an error, and so
//! are a `bool` or `Option` tag other than 0 or 1, invalid UTF-8, and a count
//! that runs past the end, which is caught before anything is allocated for
//! it. `char`, 128-bit integers and self-describing access (`deserialize_any`,
//! which `#[serde(untagged)]` and `flatten` need) are not part of the format.
//!
//! Public so that tools and tests outside the crate can read and write a
//! container body the way the vault does.

use serde::de::{self, DeserializeSeed, IntoDeserializer, Visitor};
use serde::ser::{self, Serialize};
use serde::Deserialize;
use std::fmt;

/// Why a value could not be encoded or decoded.
#[derive(Debug, PartialEq, Eq)]
pub enum WireError {
    /// The input ended inside a value.
    Eof,
    /// The value ended before the input did.
    TrailingBytes,
    /// A `bool` byte other than 0 or 1.
    InvalidBool(u8),
    /// An `Option` tag other than 0 or 1.
    InvalidTag(u8),
    InvalidUtf8,
    /// A count this platform's `usize` cannot hold.
    LengthOverflow,
    /// Larger than the limit the caller set.
    TooLarge,
    /// A sequence or map serialized without saying how long it is.
    UnknownLength,
    /// Not part of the format (see the module documentation).
    Unsupported(&'static str),
    /// A message from a type's own serde implementation.
    Custom(String),
}

impl fmt::Display for WireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Eof => f.write_str("the input ended inside a value"),
            Self::TrailingBytes => f.write_str("bytes follow the value"),
            Self::InvalidBool(b) => write!(f, "{b} is not a bool"),
            Self::InvalidTag(t) => write!(f, "{t} is not an Option tag"),
            Self::InvalidUtf8 => f.write_str("a string is not UTF-8"),
            Self::LengthOverflow => f.write_str("a count does not fit in memory"),
            Self::TooLarge => f.write_str("larger than the limit"),
            Self::UnknownLength => f.write_str("a sequence without a length"),
            Self::Unsupported(what) => write!(f, "{what} is not part of the format"),
            Self::Custom(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for WireError {}

impl ser::Error for WireError {
    fn custom<T: fmt::Display>(message: T) -> Self {
        Self::Custom(message.to_string())
    }
}

impl de::Error for WireError {
    fn custom<T: fmt::Display>(message: T) -> Self {
        Self::Custom(message.to_string())
    }
}

type Result<T> = std::result::Result<T, WireError>;

/// `value` in the format, refused when it comes to more than `limit` bytes.
pub fn encode<T: Serialize + ?Sized>(value: &T, limit: usize) -> Result<Vec<u8>> {
    let mut encoder = Encoder { out: Vec::new() };
    value.serialize(&mut encoder)?;
    if encoder.out.len() > limit {
        return Err(WireError::TooLarge);
    }
    Ok(encoder.out)
}

/// The `T` that `bytes` holds, all of them and nothing else. Input longer than
/// `limit` is refused before anything is read.
pub fn decode<'de, T: Deserialize<'de>>(bytes: &'de [u8], limit: usize) -> Result<T> {
    if bytes.len() > limit {
        return Err(WireError::TooLarge);
    }
    let mut decoder = Decoder { input: bytes };
    let value = T::deserialize(&mut decoder)?;
    if !decoder.input.is_empty() {
        return Err(WireError::TrailingBytes);
    }
    Ok(value)
}

struct Encoder {
    out: Vec<u8>,
}

impl Encoder {
    fn count(&mut self, n: usize) {
        self.out.extend_from_slice(&(n as u64).to_le_bytes());
    }
}

impl ser::Serializer for &mut Encoder {
    type Ok = ();
    type Error = WireError;
    type SerializeSeq = Self;
    type SerializeTuple = Self;
    type SerializeTupleStruct = Self;
    type SerializeTupleVariant = Self;
    type SerializeMap = Self;
    type SerializeStruct = Self;
    type SerializeStructVariant = Self;

    fn serialize_bool(self, v: bool) -> Result<()> {
        self.out.push(u8::from(v));
        Ok(())
    }
    fn serialize_i8(self, v: i8) -> Result<()> {
        self.out.extend_from_slice(&v.to_le_bytes());
        Ok(())
    }
    fn serialize_i16(self, v: i16) -> Result<()> {
        self.out.extend_from_slice(&v.to_le_bytes());
        Ok(())
    }
    fn serialize_i32(self, v: i32) -> Result<()> {
        self.out.extend_from_slice(&v.to_le_bytes());
        Ok(())
    }
    fn serialize_i64(self, v: i64) -> Result<()> {
        self.out.extend_from_slice(&v.to_le_bytes());
        Ok(())
    }
    fn serialize_u8(self, v: u8) -> Result<()> {
        self.out.push(v);
        Ok(())
    }
    fn serialize_u16(self, v: u16) -> Result<()> {
        self.out.extend_from_slice(&v.to_le_bytes());
        Ok(())
    }
    fn serialize_u32(self, v: u32) -> Result<()> {
        self.out.extend_from_slice(&v.to_le_bytes());
        Ok(())
    }
    fn serialize_u64(self, v: u64) -> Result<()> {
        self.out.extend_from_slice(&v.to_le_bytes());
        Ok(())
    }
    fn serialize_f32(self, v: f32) -> Result<()> {
        self.out.extend_from_slice(&v.to_le_bytes());
        Ok(())
    }
    fn serialize_f64(self, v: f64) -> Result<()> {
        self.out.extend_from_slice(&v.to_le_bytes());
        Ok(())
    }
    fn serialize_char(self, _: char) -> Result<()> {
        Err(WireError::Unsupported("char"))
    }
    fn serialize_str(self, v: &str) -> Result<()> {
        self.serialize_bytes(v.as_bytes())
    }
    fn serialize_bytes(self, v: &[u8]) -> Result<()> {
        self.count(v.len());
        self.out.extend_from_slice(v);
        Ok(())
    }
    fn serialize_none(self) -> Result<()> {
        self.out.push(0);
        Ok(())
    }
    fn serialize_some<T: Serialize + ?Sized>(self, value: &T) -> Result<()> {
        self.out.push(1);
        value.serialize(self)
    }
    fn serialize_unit(self) -> Result<()> {
        Ok(())
    }
    fn serialize_unit_struct(self, _: &'static str) -> Result<()> {
        Ok(())
    }
    fn serialize_unit_variant(self, _: &'static str, index: u32, _: &'static str) -> Result<()> {
        self.serialize_u32(index)
    }
    fn serialize_newtype_struct<T: Serialize + ?Sized>(
        self,
        _: &'static str,
        value: &T,
    ) -> Result<()> {
        value.serialize(self)
    }
    fn serialize_newtype_variant<T: Serialize + ?Sized>(
        self,
        _: &'static str,
        index: u32,
        _: &'static str,
        value: &T,
    ) -> Result<()> {
        self.out.extend_from_slice(&index.to_le_bytes());
        value.serialize(self)
    }
    fn serialize_seq(self, len: Option<usize>) -> Result<Self> {
        self.count(len.ok_or(WireError::UnknownLength)?);
        Ok(self)
    }
    fn serialize_tuple(self, _: usize) -> Result<Self> {
        Ok(self)
    }
    fn serialize_tuple_struct(self, _: &'static str, _: usize) -> Result<Self> {
        Ok(self)
    }
    fn serialize_tuple_variant(
        self,
        _: &'static str,
        index: u32,
        _: &'static str,
        _: usize,
    ) -> Result<Self> {
        self.out.extend_from_slice(&index.to_le_bytes());
        Ok(self)
    }
    fn serialize_map(self, len: Option<usize>) -> Result<Self> {
        self.count(len.ok_or(WireError::UnknownLength)?);
        Ok(self)
    }
    fn serialize_struct(self, _: &'static str, _: usize) -> Result<Self> {
        Ok(self)
    }
    fn serialize_struct_variant(
        self,
        _: &'static str,
        index: u32,
        _: &'static str,
        _: usize,
    ) -> Result<Self> {
        self.out.extend_from_slice(&index.to_le_bytes());
        Ok(self)
    }
    fn is_human_readable(&self) -> bool {
        false
    }
}

impl ser::SerializeSeq for &mut Encoder {
    type Ok = ();
    type Error = WireError;
    fn serialize_element<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<()> {
        value.serialize(&mut **self)
    }
    fn end(self) -> Result<()> {
        Ok(())
    }
}

impl ser::SerializeTuple for &mut Encoder {
    type Ok = ();
    type Error = WireError;
    fn serialize_element<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<()> {
        value.serialize(&mut **self)
    }
    fn end(self) -> Result<()> {
        Ok(())
    }
}

impl ser::SerializeTupleStruct for &mut Encoder {
    type Ok = ();
    type Error = WireError;
    fn serialize_field<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<()> {
        value.serialize(&mut **self)
    }
    fn end(self) -> Result<()> {
        Ok(())
    }
}

impl ser::SerializeTupleVariant for &mut Encoder {
    type Ok = ();
    type Error = WireError;
    fn serialize_field<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<()> {
        value.serialize(&mut **self)
    }
    fn end(self) -> Result<()> {
        Ok(())
    }
}

impl ser::SerializeMap for &mut Encoder {
    type Ok = ();
    type Error = WireError;
    fn serialize_key<T: Serialize + ?Sized>(&mut self, key: &T) -> Result<()> {
        key.serialize(&mut **self)
    }
    fn serialize_value<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<()> {
        value.serialize(&mut **self)
    }
    fn end(self) -> Result<()> {
        Ok(())
    }
}

impl ser::SerializeStruct for &mut Encoder {
    type Ok = ();
    type Error = WireError;
    fn serialize_field<T: Serialize + ?Sized>(&mut self, _: &'static str, value: &T) -> Result<()> {
        value.serialize(&mut **self)
    }
    fn end(self) -> Result<()> {
        Ok(())
    }
}

impl ser::SerializeStructVariant for &mut Encoder {
    type Ok = ();
    type Error = WireError;
    fn serialize_field<T: Serialize + ?Sized>(&mut self, _: &'static str, value: &T) -> Result<()> {
        value.serialize(&mut **self)
    }
    fn end(self) -> Result<()> {
        Ok(())
    }
}

struct Decoder<'de> {
    /// What is left to read.
    input: &'de [u8],
}

impl<'de> Decoder<'de> {
    fn take(&mut self, n: usize) -> Result<&'de [u8]> {
        if n > self.input.len() {
            return Err(WireError::Eof);
        }
        let (head, rest) = self.input.split_at(n);
        self.input = rest;
        Ok(head)
    }

    fn fixed<const N: usize>(&mut self) -> Result<[u8; N]> {
        let mut bytes = [0; N];
        bytes.copy_from_slice(self.take(N)?);
        Ok(bytes)
    }

    fn count(&mut self) -> Result<usize> {
        usize::try_from(u64::from_le_bytes(self.fixed()?)).map_err(|_| WireError::LengthOverflow)
    }

    fn tag(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
}

impl<'de> de::Deserializer<'de> for &mut Decoder<'de> {
    type Error = WireError;

    fn deserialize_any<V: Visitor<'de>>(self, _: V) -> Result<V::Value> {
        Err(WireError::Unsupported("self-describing access"))
    }
    fn deserialize_bool<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        match self.tag()? {
            0 => visitor.visit_bool(false),
            1 => visitor.visit_bool(true),
            other => Err(WireError::InvalidBool(other)),
        }
    }
    fn deserialize_i8<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        visitor.visit_i8(i8::from_le_bytes(self.fixed()?))
    }
    fn deserialize_i16<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        visitor.visit_i16(i16::from_le_bytes(self.fixed()?))
    }
    fn deserialize_i32<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        visitor.visit_i32(i32::from_le_bytes(self.fixed()?))
    }
    fn deserialize_i64<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        visitor.visit_i64(i64::from_le_bytes(self.fixed()?))
    }
    fn deserialize_u8<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        visitor.visit_u8(self.tag()?)
    }
    fn deserialize_u16<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        visitor.visit_u16(u16::from_le_bytes(self.fixed()?))
    }
    fn deserialize_u32<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        visitor.visit_u32(u32::from_le_bytes(self.fixed()?))
    }
    fn deserialize_u64<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        visitor.visit_u64(u64::from_le_bytes(self.fixed()?))
    }
    fn deserialize_f32<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        visitor.visit_f32(f32::from_le_bytes(self.fixed()?))
    }
    fn deserialize_f64<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        visitor.visit_f64(f64::from_le_bytes(self.fixed()?))
    }
    fn deserialize_char<V: Visitor<'de>>(self, _: V) -> Result<V::Value> {
        Err(WireError::Unsupported("char"))
    }
    fn deserialize_str<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        let n = self.count()?;
        let text = std::str::from_utf8(self.take(n)?).map_err(|_| WireError::InvalidUtf8)?;
        visitor.visit_borrowed_str(text)
    }
    fn deserialize_string<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        self.deserialize_str(visitor)
    }
    fn deserialize_bytes<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        let n = self.count()?;
        visitor.visit_borrowed_bytes(self.take(n)?)
    }
    fn deserialize_byte_buf<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        self.deserialize_bytes(visitor)
    }
    fn deserialize_option<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        match self.tag()? {
            0 => visitor.visit_none(),
            1 => visitor.visit_some(self),
            other => Err(WireError::InvalidTag(other)),
        }
    }
    fn deserialize_unit<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        visitor.visit_unit()
    }
    fn deserialize_unit_struct<V: Visitor<'de>>(
        self,
        _: &'static str,
        visitor: V,
    ) -> Result<V::Value> {
        visitor.visit_unit()
    }
    fn deserialize_newtype_struct<V: Visitor<'de>>(
        self,
        _: &'static str,
        visitor: V,
    ) -> Result<V::Value> {
        visitor.visit_newtype_struct(self)
    }
    fn deserialize_seq<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        let left = self.count()?;
        visitor.visit_seq(Elements {
            decoder: self,
            left,
        })
    }
    fn deserialize_tuple<V: Visitor<'de>>(self, len: usize, visitor: V) -> Result<V::Value> {
        visitor.visit_seq(Elements {
            decoder: self,
            left: len,
        })
    }
    fn deserialize_tuple_struct<V: Visitor<'de>>(
        self,
        _: &'static str,
        len: usize,
        visitor: V,
    ) -> Result<V::Value> {
        self.deserialize_tuple(len, visitor)
    }
    fn deserialize_map<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        let left = self.count()?;
        visitor.visit_map(Elements {
            decoder: self,
            left,
        })
    }
    fn deserialize_struct<V: Visitor<'de>>(
        self,
        _: &'static str,
        fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value> {
        self.deserialize_tuple(fields.len(), visitor)
    }
    fn deserialize_enum<V: Visitor<'de>>(
        self,
        _: &'static str,
        _: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value> {
        visitor.visit_enum(self)
    }
    fn deserialize_identifier<V: Visitor<'de>>(self, _: V) -> Result<V::Value> {
        Err(WireError::Unsupported("identifiers"))
    }
    fn deserialize_ignored_any<V: Visitor<'de>>(self, _: V) -> Result<V::Value> {
        Err(WireError::Unsupported("skipping a value"))
    }
    fn is_human_readable(&self) -> bool {
        false
    }
}

/// The elements of a sequence, tuple or struct, or the entries of a map: as
/// many as the count said, no more.
struct Elements<'a, 'de> {
    decoder: &'a mut Decoder<'de>,
    left: usize,
}

impl<'de> de::SeqAccess<'de> for Elements<'_, 'de> {
    type Error = WireError;
    fn next_element_seed<T: DeserializeSeed<'de>>(&mut self, seed: T) -> Result<Option<T::Value>> {
        if self.left == 0 {
            return Ok(None);
        }
        self.left -= 1;
        seed.deserialize(&mut *self.decoder).map(Some)
    }
    /// Serde caps what it reserves from this (`size_hint::cautious`), so a
    /// forged count cannot make it allocate; reading stops at the input's end.
    fn size_hint(&self) -> Option<usize> {
        Some(self.left)
    }
}

impl<'de> de::MapAccess<'de> for Elements<'_, 'de> {
    type Error = WireError;
    fn next_key_seed<K: DeserializeSeed<'de>>(&mut self, seed: K) -> Result<Option<K::Value>> {
        if self.left == 0 {
            return Ok(None);
        }
        self.left -= 1;
        seed.deserialize(&mut *self.decoder).map(Some)
    }
    fn next_value_seed<V: DeserializeSeed<'de>>(&mut self, seed: V) -> Result<V::Value> {
        seed.deserialize(&mut *self.decoder)
    }
    fn size_hint(&self) -> Option<usize> {
        Some(self.left)
    }
}

impl<'de> de::EnumAccess<'de> for &mut Decoder<'de> {
    type Error = WireError;
    type Variant = Self;
    fn variant_seed<V: DeserializeSeed<'de>>(self, seed: V) -> Result<(V::Value, Self)> {
        let index = u32::from_le_bytes(self.fixed()?);
        let value = seed.deserialize(IntoDeserializer::<WireError>::into_deserializer(index))?;
        Ok((value, self))
    }
}

impl<'de> de::VariantAccess<'de> for &mut Decoder<'de> {
    type Error = WireError;
    fn unit_variant(self) -> Result<()> {
        Ok(())
    }
    fn newtype_variant_seed<T: DeserializeSeed<'de>>(self, seed: T) -> Result<T::Value> {
        seed.deserialize(self)
    }
    fn tuple_variant<V: Visitor<'de>>(self, len: usize, visitor: V) -> Result<V::Value> {
        de::Deserializer::deserialize_tuple(self, len, visitor)
    }
    fn struct_variant<V: Visitor<'de>>(
        self,
        fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value> {
        de::Deserializer::deserialize_tuple(self, fields.len(), visitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Serialize;
    use uuid::Uuid;

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    enum Kind {
        Plain,
        Wrapped(u16),
        Named { x: u8 },
    }

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct Sample {
        flag: bool,
        small: u8,
        short: u16,
        word: u32,
        long: u64,
        signed: i64,
        text: String,
        blob: Vec<u8>,
        fixed: [u8; 3],
        none: Option<u32>,
        some: Option<u32>,
        kinds: Vec<Kind>,
        id: Uuid,
    }

    fn sample() -> Sample {
        Sample {
            flag: true,
            small: 7,
            short: 0x0102,
            word: 0x0102_0304,
            long: 1,
            signed: -2,
            text: "hé".into(),
            blob: vec![9, 8],
            fixed: [1, 2, 3],
            none: None,
            some: Some(5),
            kinds: vec![Kind::Plain, Kind::Wrapped(0x0304), Kind::Named { x: 9 }],
            id: Uuid::from_bytes(std::array::from_fn(|i| i as u8)),
        }
    }

    /// `sample()` as the format writes it, worked out by hand from the rules
    /// in the module documentation.
    const SAMPLE: &str = concat!(
        "01",               // flag
        "07",               // small
        "0201",             // short
        "04030201",         // word
        "0100000000000000", // long
        "feffffffffffffff", // signed
        "0300000000000000",
        "68c3a9", // text
        "0200000000000000",
        "0908",   // blob
        "010203", // fixed: no count
        "00",     // none
        "01",
        "05000000",         // some
        "0300000000000000", // kinds
        "00000000",         //   Plain
        "01000000",
        "0403", //   Wrapped
        "02000000",
        "09", //   Named
        "1000000000000000",
        "000102030405060708090a0b0c0d0e0f", // id: bytes
    );

    fn hex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn writes_and_reads_every_kind_of_value_exactly_as_specified() {
        let bytes = encode(&sample(), usize::MAX).unwrap();
        assert_eq!(bytes, hex(SAMPLE));
        assert_eq!(decode::<Sample>(&bytes, usize::MAX).unwrap(), sample());
    }

    #[test]
    fn refuses_input_that_is_not_exactly_one_value() {
        let good = hex(SAMPLE);
        let mut trailing = good.clone();
        trailing.push(0);
        assert_eq!(
            decode::<Sample>(&trailing, usize::MAX).unwrap_err(),
            WireError::TrailingBytes
        );
        for cut in [0, 1, good.len() / 2, good.len() - 1] {
            assert_eq!(
                decode::<Sample>(&good[..cut], usize::MAX).unwrap_err(),
                WireError::Eof
            );
        }

        let mut bad_bool = good.clone();
        bad_bool[0] = 2;
        assert_eq!(
            decode::<Sample>(&bad_bool, usize::MAX).unwrap_err(),
            WireError::InvalidBool(2)
        );

        // The `none` tag, after flag..fixed: 1+1+2+4+8+8+(8+3)+(8+2)+3 bytes.
        let mut bad_tag = good.clone();
        bad_tag[48] = 7;
        assert_eq!(
            decode::<Sample>(&bad_tag, usize::MAX).unwrap_err(),
            WireError::InvalidTag(7)
        );

        let mut bad_text = good;
        bad_text[32] = 0xff;
        assert_eq!(
            decode::<Sample>(&bad_text, usize::MAX).unwrap_err(),
            WireError::InvalidUtf8
        );
    }

    #[test]
    fn a_forged_count_runs_into_the_end_of_the_input_without_allocating() {
        let mut forged = u64::MAX.to_le_bytes().to_vec();
        forged.extend_from_slice(&[1, 2, 3]);
        assert!(decode::<Vec<u8>>(&forged, usize::MAX).is_err());
        assert!(decode::<Vec<Vec<u8>>>(&forged, usize::MAX).is_err());
        assert!(decode::<String>(&forged, usize::MAX).is_err());
    }

    #[test]
    fn respects_the_limit_both_ways() {
        let bytes = encode(&[1u8, 2, 3], 3).unwrap();
        assert_eq!(encode(&[1u8, 2, 3], 2).unwrap_err(), WireError::TooLarge);
        assert_eq!(
            decode::<[u8; 3]>(&bytes, 2).unwrap_err(),
            WireError::TooLarge
        );
    }

    #[test]
    fn has_no_self_describing_escape_hatches() {
        #[derive(Debug, Serialize, Deserialize)]
        #[serde(untagged)]
        enum Either {
            Number(u32),
            Text(String),
        }
        let bytes = encode(&Either::Number(1), usize::MAX).unwrap();
        assert!(decode::<Either>(&bytes, usize::MAX).is_err());
        assert_eq!(
            encode(&'x', usize::MAX).unwrap_err(),
            WireError::Unsupported("char")
        );
    }
}
