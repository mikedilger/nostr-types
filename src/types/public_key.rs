use crate::{Error, PrivateKey};
use bech32::{FromBase32, ToBase32};
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
    ///
    /// Consider converting `.into()` a `PublicKeyHex` which is a wrapped type rather than a naked `String`
    pub fn as_hex_string(&self) -> String {
        hex::encode(self.0.to_bytes())
    }

    /// Create from a hexadecimal string
    pub fn try_from_hex_string(v: &str) -> Result<PublicKey, Error> {
        let vec: Vec<u8> = hex::decode(v)?;
        // if it's not 32 bytes, dont even try because k256 code has panics in it
        if vec.len() != 32 {
            Err(Error::InvalidPublicKey)
        } else {
            Ok(PublicKey(VerifyingKey::from_bytes(&vec)?))
        }
    }

    /// Export as a bech32 encoded string
    pub fn try_as_bech32_string(&self) -> Result<String, Error> {
        Ok(bech32::encode(
            "npub",
            self.0.to_bytes().to_vec().to_base32(),
            bech32::Variant::Bech32,
        )?)
    }

    /// Import from a bech32 encoded string
    pub fn try_from_bech32_string(s: &str) -> Result<PublicKey, Error> {
        let data = bech32::decode(s)?;
        if data.0 != "npub" {
            Err(Error::WrongBech32("npub".to_string(), data.0))
        } else {
            let decoded = Vec::<u8>::from_base32(&data.1)?;
            if decoded.len() != 32 {
                Err(Error::InvalidPublicKey)
            } else {
                Ok(PublicKey(VerifyingKey::from_bytes(&decoded)?))
            }
        }
    }

    /// Import from raw bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<PublicKey, Error> {
        if bytes.len() != 32 {
            Err(Error::InvalidPublicKey)
        } else {
            Ok(PublicKey(VerifyingKey::from_bytes(bytes)?))
        }
    }

    /// Export as raw bytes
    pub fn as_bytes(&self) -> Vec<u8> {
        self.0.to_bytes().to_vec()
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
pub struct PublicKeyHex(String);

impl PublicKeyHex {
    // Mock data for testing
    #[allow(dead_code)]
    pub(crate) fn mock() -> PublicKeyHex {
        From::from(PublicKey::mock())
    }

    /// Export as a bech32 encoded string
    pub fn try_as_bech32_string(&self) -> Result<String, Error> {
        let vec: Vec<u8> = hex::decode(&self.0)?;
        Ok(bech32::encode(
            "npub",
            vec.to_base32(),
            bech32::Variant::Bech32,
        )?)
    }

    /// Try from &str
    pub fn try_from_str(s: &str) -> Result<PublicKeyHex, Error> {
        Self::try_from_string(s.to_owned())
    }

    /// Try from String
    pub fn try_from_string(s: String) -> Result<PublicKeyHex, Error> {
        if s.len() != 64 {
            return Err(Error::InvalidPublicKey);
        }
        let vec: Vec<u8> = hex::decode(&s)?;
        if vec.len() != 32 {
            return Err(Error::InvalidPublicKey);
        }
        Ok(PublicKeyHex(s))
    }

    /// As &str
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Into String
    pub fn into_string(self) -> String {
        self.0
    }

    /// Prefix of
    pub fn prefix(&self, mut chars: usize) -> PublicKeyHexPrefix {
        if chars > 64 {
            chars = 64;
        }
        PublicKeyHexPrefix(self.0[0..chars].to_owned())
    }
}

impl TryFrom<&str> for PublicKeyHex {
    type Error = Error;

    fn try_from(s: &str) -> Result<PublicKeyHex, Error> {
        PublicKeyHex::try_from_str(s)
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

/// This is a public key prefix, which identifies an actor (usually a person) and is shared, as a hex string
///
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
pub struct PublicKeyHexPrefix(String);

impl PublicKeyHexPrefix {
    // Mock data for testing
    #[allow(dead_code)]
    pub(crate) fn mock() -> PublicKeyHexPrefix {
        PublicKeyHexPrefix("a872bee01f".to_owned())
    }

    /// Try from &str
    pub fn try_from_str(s: &str) -> Result<PublicKeyHexPrefix, Error> {
        Self::try_from_string(s.to_owned())
    }

    /// Try from String
    pub fn try_from_string(s: String) -> Result<PublicKeyHexPrefix, Error> {
        if s.len() > 64 {
            return Err(Error::InvalidPublicKeyPrefix);
        }
        let vec: Vec<u8> = hex::decode(&s)?;
        if vec.len() > 32 {
            return Err(Error::InvalidPublicKeyPrefix);
        }
        Ok(PublicKeyHexPrefix(s))
    }

    /// As &str
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Into String
    pub fn into_string(self) -> String {
        self.0
    }
}

impl From<PublicKeyHex> for PublicKeyHexPrefix {
    fn from(pubkey: PublicKeyHex) -> PublicKeyHexPrefix {
        PublicKeyHexPrefix(pubkey.0)
    }
}

impl TryFrom<&str> for PublicKeyHexPrefix {
    type Error = Error;

    fn try_from(s: &str) -> Result<PublicKeyHexPrefix, Error> {
        PublicKeyHexPrefix::try_from_str(s)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    test_serde! {PublicKey, test_public_key_serde}
    test_serde! {PublicKeyHex, test_public_key_hex_serde}
    test_serde! {PublicKeyHexPrefix, test_public_key_hex_prefix_serde}

    #[test]
    fn test_pubkey_bech32() {
        let pk = PublicKey::mock();

        let encoded = pk.try_as_bech32_string().unwrap();
        println!("bech32: {}", encoded);

        let decoded = PublicKey::try_from_bech32_string(&encoded).unwrap();

        assert_eq!(pk, decoded);
    }
}
