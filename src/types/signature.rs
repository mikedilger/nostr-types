use crate::{Error, Event};
use derive_more::{AsMut, AsRef, Deref, Display, From, FromStr, Into};
use k256::schnorr::Signature as KSignature;
use serde::de::Error as DeserializeError;
use serde::de::{Deserialize as De, Deserializer, Visitor};
use serde::ser::{Serialize as Se, Serializer};
use serde::{Deserialize, Serialize};
#[cfg(feature = "speedy")]
use speedy::{Context, Readable, Reader, Writable, Writer};
use std::fmt;

/// A Schnorr signature that signs an Event, taken on the Event Id field
#[derive(AsMut, AsRef, Clone, Copy, Debug, Deref, Eq, From, Into, PartialEq)]
pub struct Signature(pub KSignature);

impl Signature {
    /// Render into a hexadecimal string
    pub fn as_hex_string(&self) -> String {
        hex::encode(self.0.to_bytes())
    }

    /// Create from a hexadecimal string
    pub fn try_from_hex_string(v: &str) -> Result<Signature, Error> {
        let vec: Vec<u8> = hex::decode(v)?;
        Ok(Signature(KSignature::try_from(&*vec)?))
    }

    // Mock data for testing
    #[allow(dead_code)]
    pub(crate) fn mock() -> Signature {
        let event = Event::mock();
        event.sig
    }
}

impl Se for Signature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(self.to_bytes()))
    }
}

impl<'de> De<'de> for Signature {
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
        let vec: Vec<u8> = hex::decode(v).map_err(|e| serde::de::Error::custom(format!("{e}")))?;

        // If we don't catch this ourselves, the below from_bytes will panic when it
        // gets into an assertion within generic-array
        if vec.len() != 64 {
            return Err(serde::de::Error::custom("Signature is not 64 bytes long"));
        }

        let ksig: KSignature =
            KSignature::try_from(&*vec).map_err(|e| DeserializeError::custom(format!("{e}")))?;

        Ok(Signature(ksig))
    }
}

#[cfg(feature = "speedy")]
impl<'a, C: Context> Readable<'a, C> for Signature {
    #[inline]
    fn read_from<R: Reader<'a, C>>(reader: &mut R) -> Result<Self, C::Error> {
        let bytes = <[u8; 32]>::read_from( reader )?;
        let sig = KSignature::try_from(&bytes[..]).map_err(|e| {
            speedy::Error::custom(e)
        })?;
        Ok(Signature(sig))
    }

    #[inline]
    fn minimum_bytes_needed() -> usize {
        32
    }
}

#[cfg(feature = "speedy")]
impl<C: Context> Writable<C> for Signature {
    #[inline]
    fn write_to<T: ?Sized + Writer<C>>(&self, writer: &mut T) -> Result<(), C::Error> {
        self.0.to_bytes().write_to( writer )
    }

    #[inline]
    fn bytes_needed(&self) -> Result<usize, C::Error> {
        Ok(32)
    }
}

/// A Schnorr signature that signs an Event, taken on the Event Id field, as a hex string
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
pub struct SignatureHex(pub String);

impl SignatureHex {
    // Mock data for testing
    #[allow(dead_code)]
    pub(crate) fn mock() -> SignatureHex {
        From::from(Signature::mock())
    }
}

impl From<Signature> for SignatureHex {
    fn from(s: Signature) -> SignatureHex {
        SignatureHex(s.as_hex_string())
    }
}

impl TryFrom<SignatureHex> for Signature {
    type Error = Error;

    fn try_from(sh: SignatureHex) -> Result<Signature, Error> {
        Signature::try_from_hex_string(&sh.0)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    test_serde! {Signature, test_signature_serde}
}
