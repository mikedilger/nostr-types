use crate::Error;
use k256::schnorr::SigningKey;

/// This is a private key which is kept secret and is used to prove identity
#[allow(missing_debug_implementations)]
#[derive(Clone)]
pub struct PrivateKey(pub SigningKey);

impl PrivateKey {
    /// Render into a hexadecimal string
    pub fn as_hex_string(&self) -> String {
        hex::encode(self.0.to_bytes())
    }

    /// Create from a hexadecimal string
    pub fn try_from_hex_string(v: &str) -> Result<PrivateKey, Error> {
        let vec: Vec<u8> = hex::decode(v)?;
        Ok(PrivateKey(SigningKey::from_bytes(&vec)?))
    }
}
