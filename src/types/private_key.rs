use crate::{Error, Id, PublicKey, Signature};
use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use k256::schnorr::SigningKey;
use pbkdf2::{
    password_hash::{PasswordHasher, SaltString},
    Pbkdf2,
};
use rand_core::{OsRng, RngCore};
use zeroize::Zeroize;

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
pub enum KeySecurity {
    /// This means that the key was exposed in a way such that this library
    /// cannot ensure it's secrecy, usually either by being exported as a hex string,
    /// or by being imported from the same. Often in these cases it is displayed
    /// on the screen or left in the cut buffer or in freed memory that was not
    /// subsequently zeroed.
    Weak,

    /// This means that the key might not have been directly exposed. But it still
    /// might have as there are numerous ways you can leak it such as exporting it
    /// and then decrypting the exported key, using unsafe rust, transmuting it into
    /// a different type that doesn't protect it, or using a privileged process to
    /// scan memory. Additionally, more advanced techniques can get at your key such
    /// as hardware attacks like spectre, rowhammer, and power analysis.
    Medium,
}

/// This is a private key which is to be kept secret and is used to prove identity
#[allow(missing_debug_implementations)]
pub struct PrivateKey(SigningKey, KeySecurity);

impl PrivateKey {
    /// Generate a new `PrivateKey` (which can be used to get the `PublicKey`)
    pub fn generate() -> PrivateKey {
        let signing_key = SigningKey::random(&mut OsRng);
        PrivateKey(signing_key, KeySecurity::Medium)
    }

    /// Get the PublicKey matching this PrivateKey
    pub fn public_key(&self) -> PublicKey {
        PublicKey(self.0.verifying_key().to_owned())
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
        hex::encode(self.0.to_bytes())
    }

    /// Create from a hexadecimal string
    ///
    /// This creates a key with `KeySecurity::Weak`.  Use `generate()` or
    /// `import_encrypted()` for `KeySecurity::Medium`
    pub fn try_from_hex_string(v: &str) -> Result<PrivateKey, Error> {
        let vec: Vec<u8> = hex::decode(v)?;
        Ok(PrivateKey(SigningKey::from_bytes(&vec)?, KeySecurity::Weak))
    }

    /// Sign a 32-bit hash
    pub fn sign_id(&self, id: Id) -> Result<Signature, Error> {
        let mut rand: [u8; 32] = [0; 32];
        OsRng.fill_bytes(&mut rand);
        let signature = self.0.try_sign_prehashed(&id.0, &rand)?;
        Ok(Signature(signature))
    }

    /// Export in an encrypted form. This does not downgrade the security of
    /// the key, but you are responsible to keep it encrypted.  You should
    /// not attempt to decrypt it, only use `import_encrypted()` on it, or
    /// something similar in another library/client which also respects key
    /// security.
    pub fn export_encrypted(&self, password: &str) -> Result<String, Error> {
        let key = Self::password_to_key(password)?;

        // Generate a Random IV
        let mut iv: [u8; 16] = [0; 16];
        OsRng.fill_bytes(&mut iv);

        // AES-256-CBC encrypt
        // SECURITY NOTICE: SigningKey has a Drop trait that zeroizes. But here
        //    we are extracting the secret bytes so we can encrypt them.
        //    The variable `inner_secret` then needs to be zeroized afterwards.
        let mut inner_secret = self.0.to_bytes();
        let ciphertext = cbc::Encryptor::<aes::Aes256>::new(&key.into(), &iv.into())
            .encrypt_padded_vec_mut::<Pkcs7>(&inner_secret);
        // Here we zeroize that `inner_secret`
        inner_secret.zeroize();

        // Combine IV and ciphertext
        let mut iv_plus_ciphertext: Vec<u8> = Vec::new();
        iv_plus_ciphertext.extend(iv);
        iv_plus_ciphertext.extend(ciphertext);

        // Base64 encode
        Ok(base64::encode(iv_plus_ciphertext))
    }

    /// Import an encrypted private key which was exported with `export_encrypted()`
    /// or a compatible function in different software.
    pub fn import_encrypted(encrypted: &str, password: &str) -> Result<PrivateKey, Error> {
        let key = Self::password_to_key(password)?;

        // Base64 decode
        let iv_plus_ciphertext = base64::decode(encrypted)?;

        // Pull the IV off
        let iv: [u8; 16] = iv_plus_ciphertext[..16].try_into()?;
        let ciphertext = &iv_plus_ciphertext[16..];

        // AES-256-CBC decrypt
        // SECURITY NOTICE: SigningKey has a Drop trait that zeroizes.  But here
        //    we are decrypting the the secret bytes. The variabler `pt`
        //    needs to be zeroized
        let mut pt = cbc::Decryptor::<aes::Aes256>::new(&key.into(), &iv.into())
            .decrypt_padded_vec_mut::<Pkcs7>(ciphertext)?;
        let output = PrivateKey(SigningKey::from_bytes(&pt)?, KeySecurity::Medium);
        // Here we zeroize pt:
        pt.zeroize();

        Ok(output)
    }

    // Hash/Stretch password with pbkdf2 into a 32-byte (256-bit) key
    fn password_to_key(password: &str) -> Result<[u8; 32], Error> {
        let salt = SaltString::b64_encode(b"nostr")?;
        let password_hash = Pbkdf2.hash_password(password.as_bytes(), &salt)?;
        let password_hash_inner = password_hash.hash.unwrap();
        let key: [u8; 32] = password_hash_inner.as_bytes()[..32].try_into()?;
        Ok(key)
    }

    // Mock data for testing
    #[allow(dead_code)]
    pub(crate) fn mock() -> PrivateKey {
        PrivateKey::generate()
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_export_import() {
        let pk = PrivateKey::generate();
        let exported = pk.export_encrypted("secret").unwrap();
        let imported_pk = PrivateKey::import_encrypted(exported, "secret").unwrap();

        // Be sure the keys generate identical public keys
        assert_eq!(pk.public_key(), imported_pk.public_key());

        // Be sure the security level is still Medium
        assert_eq!(pk.key_security(), KeySecurity::Medium)
    }
}
