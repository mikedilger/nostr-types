use crate::Error;
use derive_more::{AsMut, AsRef, Deref, From, Into};
use k256::ecdsa::signature::Signature as KSignatureTrait;
use k256::schnorr::Signature as KSignature;

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
