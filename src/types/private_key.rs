use crate::{Error, PublicKey};
use derive_more::{Deref, From, Into};
use k256::schnorr::SigningKey;

/// This is a private key which is kept secret and is used to prove identity
#[allow(missing_debug_implementations)]
#[derive(Clone, Deref, From, Into)]
pub struct PrivateKey(pub SigningKey);

impl PrivateKey {
    /// Generate a new PrivateKey (which can be used to get the PublicKey)
    pub fn generate() -> PrivateKey {
        use rand_core::OsRng;
        let signing_key = SigningKey::random(&mut OsRng);
        PrivateKey(signing_key)
    }

    /// Get the PublicKey matching this PrivateKey
    pub fn public_key(&self) -> PublicKey {
        PublicKey(self.0.verifying_key().to_owned())
    }

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
