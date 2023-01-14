use crate::{Error, Id, PublicKey, Signature};
use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use bech32::{FromBase32, ToBase32};
use derive_more::Display;
use hmac::Hmac;
use k256::schnorr::SigningKey;
use pbkdf2::pbkdf2;
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::convert::TryFrom;
use std::ops::Deref;
use zeroize::Zeroize;

// This allows us to detect bad decryptions with wrong passwords.
const CHECK_VALUE: [u8; 11] = [15, 91, 241, 148, 90, 143, 101, 12, 172, 255, 103];
const HMAC_ROUNDS: u32 = 100_000;

/// This is an encrypted private key.
#[derive(Clone, Debug, Display, Serialize, Deserialize)]
pub struct EncryptedPrivateKey(pub String);

impl Deref for EncryptedPrivateKey {
    type Target = String;

    fn deref(&self) -> &String {
        &self.0
    }
}

impl EncryptedPrivateKey {
    /// Decrypt into a Private Key with a passphrase.
    ///
    /// We recommend you zeroize() the password you pass in after you are
    /// done with it.
    pub fn decrypt(&self, password: &str) -> Result<PrivateKey, Error> {
        PrivateKey::import_encrypted(self, password)
    }
}

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

    /// Export as a bech32 encoded string
    ///
    /// WARNING: This weakens the security of your key. Your key will be marked
    /// with `KeySecurity::Weak` if you execute this.
    pub fn try_as_bech32_string(&mut self) -> Result<String, Error> {
        self.1 = KeySecurity::Weak;
        Ok(bech32::encode(
            "nsec",
            self.0.to_bytes().to_vec().to_base32(),
            bech32::Variant::Bech32,
        )?)
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
                SigningKey::from_bytes(&decoded)?,
                KeySecurity::Weak,
            ))
        }
    }

    /// Sign a 32-bit hash
    pub fn sign_id(&self, id: Id) -> Result<Signature, Error> {
        let mut rand: [u8; 32] = [0; 32];
        OsRng.fill_bytes(&mut rand);
        let signature = self.0.try_sign_prehashed(&id.0, &rand)?;
        Ok(Signature(signature))
    }

    /// Export in a (non-portable) encrypted form. This does not downgrade
    /// the security of the key, but you are responsible to keep it encrypted.
    /// You should not attempt to decrypt it, only use `import_encrypted()` on
    /// it, or something similar in another library/client which also respects key
    /// security.
    ///
    /// We recommend you zeroize() the password you pass in after you are
    /// done with it.
    pub fn export_encrypted(&self, password: &str) -> Result<EncryptedPrivateKey, Error> {
        // Generate a random 16-byte salt
        let mut salt: [u8; 16] = [0; 16];
        OsRng.fill_bytes(&mut salt);
        // But force the first byte to a 1
        salt[0] = 0x01;

        // Key derivation
        let key = Self::password_to_key(password, &salt, HMAC_ROUNDS)?;

        // Generate a Random IV
        let mut iv: [u8; 16] = [0; 16];
        OsRng.fill_bytes(&mut iv);

        // AES-256-CBC encrypt
        // SECURITY NOTICE: SigningKey has a Drop trait that zeroizes. But here
        //    we are extracting the secret bytes so we can encrypt them.
        //    The variable `inner_secret` then needs to be zeroized afterwards.
        let mut inner_secret: Vec<u8> = self.0.to_bytes().to_vec();

        // Add a 11-byte (128-bit) check value. If decryption doesn't yield this check
        // value we then know the decryption password was wrong.
        inner_secret.extend(CHECK_VALUE); // now 43 bytes
        inner_secret.push(self.1 as u8); // now 44 bytes
        if inner_secret.len() != 44 {
            return Err(Error::AssertionFailed(
                "Export encrypted inner secret len != 44".to_owned(),
            ));
        }

        let ciphertext = cbc::Encryptor::<aes::Aes256>::new(&key.into(), &iv.into())
            .encrypt_padded_vec_mut::<Pkcs7>(&inner_secret); // now 48 bytes
        if ciphertext.len() != 48 {
            return Err(Error::AssertionFailed(
                "Export encrypted ciphertext len != 48".to_owned(),
            ));
        }

        // Here we zeroize that `inner_secret`
        inner_secret.zeroize();

        // Combine salt, IV and ciphertext
        let mut concatenation: Vec<u8> = Vec::new();
        concatenation.extend(salt);
        concatenation.extend(iv);
        concatenation.extend(ciphertext); // now 80 bytes
        if concatenation.len() != 80 {
            return Err(Error::AssertionFailed(
                "Export encrypted concatenation len != 80".to_owned(),
            ));
        }

        // bech32 encode
        Ok(EncryptedPrivateKey(bech32::encode(
            "ncryptsec",
            concatenation.to_base32(),
            bech32::Variant::Bech32,
        )?))
    }

    /// Import an encrypted private key which was exported with `export_encrypted()`.
    ///
    /// We recommend you zeroize() the password you pass in after you are
    /// done with it.
    ///
    /// This is backwards-compatible with keys that were exported with older code.
    pub fn import_encrypted(
        encrypted: &EncryptedPrivateKey,
        password: &str,
    ) -> Result<PrivateKey, Error> {
        if encrypted.0.starts_with("ncryptsec1") {
            Self::import_encrypted_bech32(encrypted, password)
        } else {
            Self::import_encrypted_base64(encrypted, password)
        }
    }

    fn import_encrypted_bech32(
        encrypted: &EncryptedPrivateKey,
        password: &str,
    ) -> Result<PrivateKey, Error> {
        // bech32 decode
        let data = bech32::decode(&encrypted.0)?;
        if data.0 != "ncryptsec" {
            return Err(Error::WrongBech32("ncryptsec".to_string(), data.0));
        }
        Self::import_encrypted_inner(Vec::<u8>::from_base32(&data.1)?, password)
    }

    fn import_encrypted_base64(
        encrypted: &EncryptedPrivateKey,
        password: &str,
    ) -> Result<PrivateKey, Error> {
        let concatenation = base64::decode(&encrypted.0)?; // 64 or 80 bytes
        Self::import_encrypted_inner(concatenation, password)
    }

    fn import_encrypted_inner(concatenation: Vec<u8>, password: &str) -> Result<PrivateKey, Error> {
        if concatenation.len() == 64 {
            return Self::import_encrypted_inner_version1(concatenation, password);
        }
        if concatenation.len() != 80 {
            return Err(Error::InvalidEncryptedPrivateKey);
        }

        // Break into parts
        let salt: [u8; 16] = concatenation[..16].try_into()?;
        let iv: [u8; 16] = concatenation[16..32].try_into()?;
        let ciphertext = &concatenation[32..]; // 48 bytes

        let key = Self::password_to_key(password, &salt, HMAC_ROUNDS)?;

        // AES-256-CBC decrypt
        // SECURITY NOTICE: SigningKey has a Drop trait that zeroizes.  But here
        //    we are decrypting the the secret bytes. The variable `plaintext`
        //    needs to be zeroized
        let mut plaintext = cbc::Decryptor::<aes::Aes256>::new(&key.into(), &iv.into())
            .decrypt_padded_vec_mut::<Pkcs7>(ciphertext)?; // 44 bytes
        if plaintext.len() != 44 {
            return Err(Error::InvalidEncryptedPrivateKey);
            //return Err(Error::AssertionFailed("Import encrypted plaintext len != 44".to_owned()));
        }

        // Verify the check value
        if plaintext[plaintext.len() - 12..plaintext.len() - 1] != CHECK_VALUE {
            return Err(Error::WrongDecryptionPassword);
        }

        // Get the key security
        let ks = KeySecurity::try_from(plaintext[plaintext.len() - 1])?;
        let output = PrivateKey(
            SigningKey::from_bytes(&plaintext[..plaintext.len() - 12])?,
            ks,
        );

        // Here we zeroize plaintext:
        plaintext.zeroize();

        Ok(output)
    }

    // version1 had a fixed salt "nostr" and was 4096 rounds (was also base64 encoded)
    fn import_encrypted_inner_version1(
        iv_plus_ciphertext: Vec<u8>,
        password: &str,
    ) -> Result<PrivateKey, Error> {
        let key = Self::password_to_key(password, b"nostr", 4096)?;

        if iv_plus_ciphertext.len() < 48 {
            // Should be 64 from padding, but we pushed in 48
            return Err(Error::InvalidEncryptedPrivateKey);
        }

        // Pull the IV off
        let iv: [u8; 16] = iv_plus_ciphertext[..16].try_into()?;
        let ciphertext = &iv_plus_ciphertext[16..]; // 64 bytes

        // AES-256-CBC decrypt
        // SECURITY NOTICE: SigningKey has a Drop trait that zeroizes.  But here
        //    we are decrypting the the secret bytes. The variabler `pt`
        //    needs to be zeroized
        let mut pt = cbc::Decryptor::<aes::Aes256>::new(&key.into(), &iv.into())
            .decrypt_padded_vec_mut::<Pkcs7>(ciphertext)?; // 48 bytes

        // Verify the check value
        if pt[pt.len() - 12..pt.len() - 1] != CHECK_VALUE {
            return Err(Error::WrongDecryptionPassword);
        }

        // Get the key security
        let ks = KeySecurity::try_from(pt[pt.len() - 1])?;
        let output = PrivateKey(SigningKey::from_bytes(&pt[..pt.len() - 12])?, ks);

        // Here we zeroize pt:
        pt.zeroize();

        Ok(output)
    }

    // Hash/Stretch password with pbkdf2 into a 32-byte (256-bit) key
    fn password_to_key(password: &str, salt: &[u8], rounds: u32) -> Result<[u8; 32], Error> {
        let mut key: [u8; 32] = [0; 32];
        pbkdf2::<Hmac<Sha256>>(password.as_bytes(), salt, rounds, &mut key);
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
        println!("{}", exported);
        let imported_pk = PrivateKey::import_encrypted(&exported, "secret").unwrap();

        // Be sure the keys generate identical public keys
        assert_eq!(pk.public_key(), imported_pk.public_key());

        // Be sure the security level is still Medium
        assert_eq!(pk.key_security(), KeySecurity::Medium)
    }

    #[test]
    fn test_import_old_formats() {
        let decrypted = "a28129ab0b70c8d5e75aaf510ec00bff47fde7ca4ab9e3d9315c77edc86f037f";

        // pre-salt base64
        let encrypted = EncryptedPrivateKey("F+VYIvTCtIZn4c6owPMZyu4Zn5DH9T5XcgZWmFG/3ma4C3PazTTQxQcIF+G+daeFlkqsZiNIh9bcmZ5pfdRPyg==".to_owned());
        assert_eq!(
            encrypted.decrypt("nostr").unwrap().as_hex_string(),
            decrypted
        );

        // post-salt base64
        let encrypted = EncryptedPrivateKey("AZQYNwAGULWyKweTtw6WCljV+1cil8IMRxfZ7Rs3nCfwbVQBV56U6eV9ps3S1wU7ieCx6EraY9Uqdsw71TY5Yv/Ep6yGcy9m1h4YozuxWQE=".to_owned());
        assert_eq!(
            encrypted.decrypt("nostr").unwrap().as_hex_string(),
            decrypted
        );
    }

    #[test]
    fn test_privkey_bech32() {
        let mut pk = PrivateKey::mock();

        let encoded = pk.try_as_bech32_string().unwrap();
        println!("bech32: {}", encoded);

        let decoded = PrivateKey::try_from_bech32_string(&encoded).unwrap();

        assert_eq!(pk.0.to_bytes(), decoded.0.to_bytes());
        assert_eq!(decoded.1, KeySecurity::Weak);
    }
}
