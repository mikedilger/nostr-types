use crate::{Error, Id, PublicKey, Signature};
use bech32::{FromBase32, ToBase32};
use rand_core::OsRng;
use std::convert::TryFrom;

mod encrypted_private_key;
pub use encrypted_private_key::*;

mod content_encryption;
pub use content_encryption::*;

/// This indicates the security of the key by keeping track of whether the
/// secret key material was handled carefully. If the secret is exposed in any
/// way, or leaked and the memory not zeroed, the key security drops to Weak.
///
/// This is a Best Effort tag. There are ways to leak the key and still have this
/// tag claim the key is Medium security. So Medium really means it might not
/// have leaked, whereas Weak means we know that it definately did leak.
///
/// We offer no Strong security via the PrivateKey structure. If we support
/// hardware tokens in the future, it will probably be via a different structure.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum KeySecurity {
    /// This means that the key was exposed in a way such that this library
    /// cannot ensure it's secrecy, usually either by being exported as a hex string,
    /// or by being imported from the same. Often in these cases it is displayed
    /// on the screen or left in the cut buffer or in freed memory that was not
    /// subsequently zeroed.
    Weak = 0,

    /// This means that the key might not have been directly exposed. But it still
    /// might have as there are numerous ways you can leak it such as exporting it
    /// and then decrypting the exported key, using unsafe rust, transmuting it into
    /// a different type that doesn't protect it, or using a privileged process to
    /// scan memory. Additionally, more advanced techniques can get at your key such
    /// as hardware attacks like spectre, rowhammer, and power analysis.
    Medium = 1,
}

impl TryFrom<u8> for KeySecurity {
    type Error = Error;

    fn try_from(i: u8) -> Result<KeySecurity, Error> {
        if i == 0 {
            Ok(KeySecurity::Weak)
        } else if i == 1 {
            Ok(KeySecurity::Medium)
        } else {
            Err(Error::UnknownKeySecurity(i))
        }
    }
}

/// This is a private key which is to be kept secret and is used to prove identity
#[allow(missing_debug_implementations)]
pub struct PrivateKey(secp256k1::SecretKey, KeySecurity);

impl Default for PrivateKey {
    fn default() -> Self {
        Self::new()
    }
}

impl PrivateKey {
    /// Generate a new `PrivateKey` (which can be used to get the `PublicKey`)
    #[inline]
    pub fn new() -> PrivateKey {
        Self::generate()
    }

    /// Generate a new `PrivateKey` (which can be used to get the `PublicKey`)
    pub fn generate() -> PrivateKey {
        let secret_key = secp256k1::SecretKey::new(&mut OsRng);
        PrivateKey(secret_key, KeySecurity::Medium)
    }

    /// Get the PublicKey matching this PrivateKey
    pub fn public_key(&self) -> PublicKey {
        let (xopk, _parity) = self.0.x_only_public_key(secp256k1::SECP256K1);
        PublicKey::from_bytes(&xopk.serialize(), false).unwrap()
    }

    /// Get the security level of the private key
    pub fn key_security(&self) -> KeySecurity {
        self.1
    }

    /// Render into a hexadecimal string
    ///
    /// WARNING: This weakens the security of your key. Your key will be marked
    /// with `KeySecurity::Weak` if you execute this.
    pub fn as_hex_string(&mut self) -> String {
        self.1 = KeySecurity::Weak;
        hex::encode(self.0.secret_bytes())
    }

    /// Create from a hexadecimal string
    ///
    /// This creates a key with `KeySecurity::Weak`.  Use `generate()` or
    /// `import_encrypted()` for `KeySecurity::Medium`
    pub fn try_from_hex_string(v: &str) -> Result<PrivateKey, Error> {
        let vec: Vec<u8> = hex::decode(v)?;
        Ok(PrivateKey(
            secp256k1::SecretKey::from_slice(&vec)?,
            KeySecurity::Weak,
        ))
    }

    /// Export as a bech32 encoded string
    ///
    /// WARNING: This weakens the security of your key. Your key will be marked
    /// with `KeySecurity::Weak` if you execute this.
    pub fn as_bech32_string(&mut self) -> String {
        self.1 = KeySecurity::Weak;
        bech32::encode(
            "nsec",
            self.0.secret_bytes().as_slice().to_base32(),
            bech32::Variant::Bech32,
        )
        .unwrap()
    }

    /// Import from a bech32 encoded string
    ///
    /// This creates a key with `KeySecurity::Weak`.  Use `generate()` or
    /// `import_encrypted()` for `KeySecurity::Medium`
    pub fn try_from_bech32_string(s: &str) -> Result<PrivateKey, Error> {
        let data = bech32::decode(s)?;
        if data.0 != "nsec" {
            Err(Error::WrongBech32("nsec".to_string(), data.0))
        } else {
            let decoded = Vec::<u8>::from_base32(&data.1)?;
            Ok(PrivateKey(
                secp256k1::SecretKey::from_slice(&decoded)?,
                KeySecurity::Weak,
            ))
        }
    }

    /// Sign a 32-bit hash
    pub fn sign_id(&self, id: Id) -> Result<Signature, Error> {
        let keypair = secp256k1::Keypair::from_secret_key(secp256k1::SECP256K1, &self.0);
        let message = secp256k1::Message::from_digest_slice(id.0.as_slice())?;
        Ok(Signature(keypair.sign_schnorr(message)))
    }

    /// Sign a message (this hashes with SHA-256 first internally)
    pub fn sign(&self, message: &[u8]) -> Result<Signature, Error> {
        use secp256k1::hashes::sha256;
        let keypair = secp256k1::Keypair::from_secret_key(secp256k1::SECP256K1, &self.0);
        let message = secp256k1::Message::from_hashed_data::<sha256::Hash>(message);
        Ok(Signature(keypair.sign_schnorr(message)))
    }

    // Mock data for testing
    #[allow(dead_code)]
    pub(crate) fn mock() -> PrivateKey {
        PrivateKey::generate()
    }
}

impl Drop for PrivateKey {
    fn drop(&mut self) {
        self.0.non_secure_erase();
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_privkey_bech32() {
        let mut pk = PrivateKey::mock();

        let encoded = pk.as_bech32_string();
        println!("bech32: {encoded}");

        let decoded = PrivateKey::try_from_bech32_string(&encoded).unwrap();

        assert_eq!(pk.0.secret_bytes(), decoded.0.secret_bytes());
        assert_eq!(decoded.1, KeySecurity::Weak);
    }
}
