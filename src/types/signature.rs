use crate::Error;
use derive_more::{AsMut, AsRef, Deref, From, Into};
use k256::ecdsa::signature::Signature as KSignatureTrait;
use k256::schnorr::Signature as KSignature;
use serde::de::Error as DeError;
use serde::de::{Deserialize, Deserializer, Visitor};
use serde::ser::{Serialize, Serializer};
use std::fmt;

/// A Schnorr signature that signs an Event, taken on the Event Id field
#[derive(AsMut, AsRef, Clone, Copy, Debug, Deref, Eq, From, Into, PartialEq)]
pub struct Signature(pub KSignature);

impl Signature {
    /// Render into a hexadecimal string
    pub fn as_hex_string(&self) -> String {
        hex::encode(self.0.as_bytes())
    }

    /// Create from a hexadecimal string
    pub fn try_from_hex_string(v: &str) -> Result<Signature, Error> {
        let vec: Vec<u8> = hex::decode(v)?;
        Ok(Signature(KSignature::from_bytes(&vec)?))
    }
}

impl Serialize for Signature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(self.0))
    }
}

impl<'de> Deserialize<'de> for Signature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_str(SignatureVisitor)
    }
}

struct SignatureVisitor;

impl Visitor<'_> for SignatureVisitor {
    type Value = Signature;

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "a hexadecimal string representing 64 bytes")
    }

    fn visit_str<E>(self, v: &str) -> Result<Signature, E>
    where
        E: serde::de::Error,
    {
        let vec: Vec<u8> =
            hex::decode(v).map_err(|e| serde::de::Error::custom(format!("{}", e)))?;

        let ksig: KSignature =
            KSignature::from_bytes(&vec).map_err(|e| DeError::custom(format!("{}", e)))?;

        Ok(Signature(ksig))
    }
}
