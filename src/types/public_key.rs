use crate::{Error, PrivateKey, Signature};
use bech32::{FromBase32, ToBase32};
use derive_more::{AsMut, AsRef, Deref, Display, From, FromStr, Into};
use secp256k1::SECP256K1;
use serde::de::{Deserializer, Visitor};
use serde::ser::Serializer;
use serde::{Deserialize, Serialize};
#[cfg(feature = "speedy")]
use speedy::{Context, Readable, Reader, Writable, Writer};
use std::fmt;
use std::hash::{Hash, Hasher};

/// This is a public key, which identifies an actor (usually a person) and is shared.
#[derive(AsMut, AsRef, Copy, Clone, Debug, Deref, Eq, From, Into, PartialEq, Serialize, Deserialize)]
pub struct PublicKey(pub secp256k1::XOnlyPublicKey);

impl PublicKey {
    /// Render into a hexadecimal string
    ///
    /// Consider converting `.into()` a `PublicKeyHex` which is a wrapped type rather than a naked `String`
    pub fn as_hex_string(&self) -> String {
        hex::encode(self.0.serialize())
    }

    /// Create from a hexadecimal string
    pub fn try_from_hex_string(v: &str) -> Result<PublicKey, Error> {
        let vec: Vec<u8> = hex::decode(v)?;
        // if it's not 32 bytes, dont even try
        if vec.len() != 32 {
            Err(Error::InvalidPublicKey)
        } else {
            Ok(PublicKey(secp256k1::XOnlyPublicKey::from_slice(&vec)?))
        }
    }

    /// Export as a bech32 encoded string
    pub fn as_bech32_string(&self) -> String {
        bech32::encode(
            "npub",
            self.0.serialize().as_slice().to_base32(),
            bech32::Variant::Bech32,
        )
        .unwrap()
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
                Ok(PublicKey(secp256k1::XOnlyPublicKey::from_slice(&decoded)?))
            }
        }
    }

    /// Import from raw bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<PublicKey, Error> {
        if bytes.len() != 32 {
            Err(Error::InvalidPublicKey)
        } else {
            Ok(PublicKey(secp256k1::XOnlyPublicKey::from_slice(bytes)?))
        }
    }

    /// Export as raw bytes
    pub fn as_bytes(&self) -> Vec<u8> {
        self.0.serialize().as_slice().to_vec()
    }

    /// Verify a signed message
    pub fn verify(&self, message: &[u8], signature: &Signature) -> Result<(), Error> {
        use secp256k1::hashes::sha256;
        let message = secp256k1::Message::from_hashed_data::<sha256::Hash>(message);
        Ok(SECP256K1.verify_schnorr(&signature.0, &message, self)?)
    }

    // Mock data for testing
    #[allow(dead_code)]
    pub(crate) fn mock() -> PublicKey {
        PrivateKey::generate().public_key()
    }

    #[allow(dead_code)]
    pub(crate) fn mock_deterministic() -> PublicKey {
        PublicKey::try_from_hex_string(
            "ee11a5dff40c19a555f41fe42b48f00e618c91225622ae37b6c2bb67b76c4e49",
        )
        .unwrap()
    }
}

impl Hash for PublicKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.as_hex_string().hash(state);
    }
}

#[cfg(feature = "speedy")]
impl<'a, C: Context> Readable<'a, C> for PublicKey {
    #[inline]
    fn read_from<R: Reader<'a, C>>(reader: &mut R) -> Result<Self, C::Error> {
        let bytes: Vec<u8> = reader.read_vec(32)?;
        let vk = secp256k1::XOnlyPublicKey::from_slice(&bytes).map_err(|e| speedy::Error::custom(e))?;
        Ok(PublicKey(vk))
    }

    #[inline]
    fn minimum_bytes_needed() -> usize {
        32
    }
}

#[cfg(feature = "speedy")]
impl<C: Context> Writable<C> for PublicKey {
    #[inline]
    fn write_to<T: ?Sized + Writer<C>>(&self, writer: &mut T) -> Result<(), C::Error> {
        let field_bytes = self.0.serialize();
        assert_eq!(field_bytes.as_slice().len(), 32);
        writer.write_bytes(field_bytes.as_slice())
    }

    #[inline]
    fn bytes_needed(&self) -> Result<usize, C::Error> {
        Ok(32)
    }
}

/// This is a public key, which identifies an actor (usually a person) and is shared, as a hex string
///
/// You can convert from a `PublicKey` into this with `From`/`Into`.  You can convert this back to a `PublicKey` with `TryFrom`/`TryInto`.
#[derive(AsMut, AsRef, Clone, Debug, Deref, Display, Eq, From, FromStr, Hash, Into, PartialEq)]
#[cfg_attr(feature = "speedy", derive(Readable, Writable))]
pub struct PublicKeyHex(String);

impl PublicKeyHex {
    // Mock data for testing
    #[allow(dead_code)]
    pub(crate) fn mock() -> PublicKeyHex {
        From::from(PublicKey::mock())
    }

    // Mock data for testing
    #[allow(dead_code)]
    pub(crate) fn mock_deterministic() -> PublicKeyHex {
        From::from(PublicKey::mock_deterministic())
    }

    /// Export as a bech32 encoded string
    pub fn as_bech32_string(&self) -> String {
        let vec: Vec<u8> = hex::decode(&self.0).unwrap();
        bech32::encode("npub", vec.to_base32(), bech32::Variant::Bech32).unwrap()
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
        PublicKeyHexPrefix(self.0.get(0..chars).unwrap().to_owned())
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

impl Serialize for PublicKeyHex {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for PublicKeyHex {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_str(PublicKeyHexVisitor)
    }
}

struct PublicKeyHexVisitor;

impl Visitor<'_> for PublicKeyHexVisitor {
    type Value = PublicKeyHex;

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "a lowercase hexadecimal string representing 32 bytes")
    }

    fn visit_str<E>(self, v: &str) -> Result<PublicKeyHex, E>
    where
        E: serde::de::Error,
    {
        if v.len() != 64 {
            return Err(serde::de::Error::custom(
                "PublicKeyHex is not 64 characters long",
            ));
        }

        let vec: Vec<u8> = hex::decode(v).map_err(|e| serde::de::Error::custom(format!("{e}")))?;
        if vec.len() != 32 {
            return Err(serde::de::Error::custom("Invalid PublicKeyHex"));
        }

        Ok(PublicKeyHex(v.to_owned()))
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
#[cfg_attr(feature = "speedy", derive(Readable, Writable))]
pub struct PublicKeyHexPrefix(String);

impl PublicKeyHexPrefix {
    // Mock data for testing
    #[allow(dead_code)]
    pub(crate) fn mock() -> PublicKeyHexPrefix {
        PublicKeyHexPrefix("a872bee01f6".to_owned())
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
        if s.chars().any(|c| !c.is_ascii_hexdigit()) {
            return Err(Error::InvalidPublicKeyPrefix);
        }
        // let vec: Vec<u8> = hex::decode(&s)?;
        // if vec.len() > 32 {
        //    return Err(Error::InvalidPublicKeyPrefix);
        // }
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

    /// Matches a PublicKeyhex
    pub fn matches(&self, pubkey: &PublicKeyHex) -> bool {
        pubkey.0.starts_with(&self.0)
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

        let encoded = pk.as_bech32_string();
        println!("bech32: {encoded}");

        let decoded = PublicKey::try_from_bech32_string(&encoded).unwrap();

        assert_eq!(pk, decoded);
    }

    #[cfg(feature = "speedy")]
    #[test]
    fn test_speedy_public_key() {
        let pk = PublicKey::mock();
        let bytes = pk.write_to_vec().unwrap();
        let pk2 = PublicKey::read_from_buffer(&bytes).unwrap();
        assert_eq!(pk, pk2);
    }
}
