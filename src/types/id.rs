use crate::Error;
use derive_more::{AsMut, AsRef, Deref, From, Into};

/// An event identifier, constructed as a SHA256 hash of the event fields according to NIP-01
#[derive(AsMut, AsRef, Clone, Copy, Debug, Deref, Eq, From, Into, Ord, PartialEq, PartialOrd)]
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
}
