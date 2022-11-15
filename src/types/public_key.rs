use crate::Error;
use derive_more::{AsMut, AsRef, Deref, From, Into};
use k256::schnorr::VerifyingKey;

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
}
