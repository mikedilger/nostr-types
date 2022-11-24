use crate::Error;
use derive_more::{AsMut, AsRef, Deref, Display, From, FromStr, Into};
use serde::de::{Deserializer, Visitor};
use serde::ser::Serializer;
use serde::{Deserialize, Serialize};
use std::fmt;

/// An event identifier, constructed as a SHA256 hash of the event fields according to NIP-01
#[derive(
    AsMut, AsRef, Clone, Copy, Debug, Deref, Eq, From, Hash, Into, Ord, PartialEq, PartialOrd,
)]
pub struct Id(pub [u8; 32]);

impl Id {
    /// Render into a hexadecimal string
    pub fn as_hex_string(&self) -> String {
        hex::encode(self.0)
    }

    /// Create from a hexadecimal string
    pub fn try_from_hex_string(v: &str) -> Result<Id, Error> {
        let vec: Vec<u8> = hex::decode(v)?;
        Ok(Id(vec
            .try_into()
            .map_err(|_| Error::WrongLengthHexString)?))
    }

    // Mock data for testing
    #[allow(dead_code)]
    pub(crate) fn mock() -> Id {
        Id::try_from_hex_string("5df64b33303d62afc799bdc36d178c07b2e1f0d824f31b7dc812219440affab6")
            .unwrap()
    }
}

impl Serialize for Id {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(self.0))
    }
}

impl<'de> Deserialize<'de> for Id {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_str(IdVisitor)
    }
}

struct IdVisitor;

impl Visitor<'_> for IdVisitor {
    type Value = Id;

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "a hexadecimal string representing 32 bytes")
    }

    fn visit_str<E>(self, v: &str) -> Result<Id, E>
    where
        E: serde::de::Error,
    {
        let vec: Vec<u8> =
            hex::decode(v).map_err(|e| serde::de::Error::custom(format!("{}", e)))?;

        Ok(Id(vec.try_into().map_err(|e: Vec<u8>| {
            E::custom(format!(
                "Id is not 32 bytes long. Was {} bytes long",
                e.len()
            ))
        })?))
    }
}

/// An event identifier, constructed as a SHA256 hash of the event fields according to NIP-01, as a hex string
///
/// You can convert from an `Id` into this with `From`/`Into`.  You can convert this back to an `Id` with `TryFrom`/`TryInto`.
#[derive(
    AsMut,
    AsRef,
    Clone,
    Debug,
    Deref,
    Deserialize,
    Display,
    Eq,
    From,
    FromStr,
    Hash,
    Into,
    PartialEq,
    Serialize,
)]
pub struct IdHex(pub String);

impl From<Id> for IdHex {
    fn from(i: Id) -> IdHex {
        IdHex(i.as_hex_string())
    }
}

impl TryFrom<IdHex> for Id {
    type Error = Error;

    fn try_from(h: IdHex) -> Result<Id, Error> {
        Id::try_from_hex_string(&h.0)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    test_serde! {Id, test_id_serde}
}
