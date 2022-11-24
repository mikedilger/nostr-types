use crate::{Error, PrivateKey};
use derive_more::{AsMut, AsRef, Deref, Display, From, FromStr, Into};
use k256::schnorr::VerifyingKey;
use serde::de::{Deserializer, Visitor};
use serde::ser::Serializer;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::hash::{Hash, Hasher};

/// This is a public key, which identifies an actor (usually a person) and is shared.
#[derive(AsMut, AsRef, Copy, Clone, Debug, Deref, Eq, From, Into, PartialEq)]
pub struct PublicKey(pub VerifyingKey);

impl PublicKey {
    /// Render into a hexadecimal string
    pub fn as_hex_string(&self) -> String {
        hex::encode(self.0.to_bytes())
    }

    /// Create from a hexadecimal string
    pub fn try_from_hex_string(v: &str) -> Result<PublicKey, Error> {
        let vec: Vec<u8> = hex::decode(v)?;
        Ok(PublicKey(VerifyingKey::from_bytes(&vec)?))
    }

    // Mock data for testing
    #[allow(dead_code)]
    pub(crate) fn mock() -> PublicKey {
        PrivateKey::generate().public_key()
    }
}

impl Serialize for PublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&format!("{:x}", self.0.to_bytes()))
    }
}

impl<'de> Deserialize<'de> for PublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_str(PublicKeyVisitor)
    }
}

struct PublicKeyVisitor;

impl Visitor<'_> for PublicKeyVisitor {
    type Value = PublicKey;

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "a hexadecimal string representing 32 bytes")
    }

    fn visit_str<E>(self, v: &str) -> Result<PublicKey, E>
    where
        E: serde::de::Error,
    {
        let vec: Vec<u8> =
            hex::decode(v).map_err(|e| serde::de::Error::custom(format!("{}", e)))?;

        // If we don't catch this ourselves, the below from_bytes will panic when it
        // gets into an assertion within generic-array
        if vec.len() != 32 {
            return Err(serde::de::Error::custom("Public key is not 32 bytes long"));
        }

        Ok(PublicKey(
            VerifyingKey::from_bytes(&vec)
                .map_err(|e| serde::de::Error::custom(format!("{}", e)))?,
        ))
    }
}

#[allow(clippy::derive_hash_xor_eq)]
impl Hash for PublicKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.as_hex_string().hash(state);
    }
}

/// This is a public key, which identifies an actor (usually a person) and is shared, as a hex string
///
/// You can convert from a `PublicKey` into this with `From`/`Into`.  You can convert this back to a `PublicKey` with `TryFrom`/`TryInto`.
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
pub struct PublicKeyHex(pub String);

impl PublicKeyHex {
    // Mock data for testing
    #[allow(dead_code)]
    pub(crate) fn mock() -> PublicKeyHex {
        From::from(PublicKey::mock())
    }
}

impl From<PublicKey> for PublicKeyHex {
    fn from(pk: PublicKey) -> PublicKeyHex {
        PublicKeyHex(pk.as_hex_string())
    }
}

impl TryFrom<PublicKeyHex> for PublicKey {
    type Error = Error;

    fn try_from(pkh: PublicKeyHex) -> Result<PublicKey, Error> {
        PublicKey::try_from_hex_string(&pkh.0)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    test_serde! {PublicKey, test_public_key_serde}
}
