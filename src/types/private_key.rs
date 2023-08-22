use crate::{Error, Id, PublicKey, Signature};
use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use base64::Engine;
use bech32::{FromBase32, ToBase32};
use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, Payload},
    XChaCha20Poly1305,
};
use derive_more::Display;
use hmac::Hmac;
use pbkdf2::pbkdf2;
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::convert::TryFrom;
use std::ops::Deref;
use zeroize::Zeroize;

// This allows us to detect bad decryptions with wrong passwords.
const V1_CHECK_VALUE: [u8; 11] = [15, 91, 241, 148, 90, 143, 101, 12, 172, 255, 103];
const V1_HMAC_ROUNDS: u32 = 100_000;

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

    /// Version
    ///
    /// Version -1:
    ///    PBKDF = pbkdf2-hmac-sha256 ( salt = "nostr", rounds = 4096 )
    ///    inside = concat(private_key, 15 specified bytes, key_security_byte)
    ///    encrypt = AES-256-CBC with random IV
    ///    compose = iv + ciphertext
    ///    encode = base64
    /// Version 0:
    ///    PBKDF = pbkdf2-hmac-sha256 ( salt = concat(0x1, 15 random bytes), rounds = 100000 )
    ///    inside = concat(private_key, 15 specified bytes, key_security_byte)
    ///    encrypt = AES-256-CBC with random IV
    ///    compose = salt + iv + ciphertext
    ///    encode = base64
    /// Version 1:
    ///    PBKDF = pbkdf2-hmac-sha256 ( salt = concat(0x1, 15 random bytes), rounds = 100000 )
    ///    inside = concat(private_key, 15 specified bytes, key_security_byte)
    ///    encrypt = AES-256-CBC with random IV
    ///    compose = salt + iv + ciphertext
    ///    encode = bech32('ncryptsec')
    /// Version 2:
    ///    PBKDF = scrypt ( salt = 16 random bytes, log_n = user choice, r = 8, p = 1)
    ///    inside = private_key
    ///    associated_data = key_security_byte
    ///    encrypt = XChaCha20-Poly1305
    ///    compose = concat (0x2, log_n, salt, nonce, associated_data, ciphertext)
    ///    encode = bech32('ncryptsec')
    pub fn version(&self) -> Result<i8, Error> {
        if self.0.starts_with("ncryptsec1") {
            let data = bech32::decode(&self.0)?;
            if data.0 != "ncryptsec" {
                return Err(Error::WrongBech32("ncryptsec".to_string(), data.0));
            }
            let data = Vec::<u8>::from_base32(&data.1)?;
            Ok(data[0] as i8)
        } else if self.0.len() == 64 {
            Ok(-1)
        } else {
            Ok(0) // base64 variant of v1
        }
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
pub struct PrivateKey(secp256k1::SecretKey, KeySecurity);

impl PrivateKey {
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
        let keypair = secp256k1::KeyPair::from_secret_key(secp256k1::SECP256K1, &self.0);
        let message = secp256k1::Message::from_slice(id.0.as_slice())?;
        Ok(Signature(keypair.sign_schnorr(message)))
    }

    /// Sign a message (this hashes with SHA-256 first internally)
    pub fn sign(&self, message: &[u8]) -> Result<Signature, Error> {
        use secp256k1::hashes::sha256;
        let keypair = secp256k1::KeyPair::from_secret_key(secp256k1::SECP256K1, &self.0);
        let message = secp256k1::Message::from_hashed_data::<sha256::Hash>(message);
        Ok(Signature(keypair.sign_schnorr(message)))
    }

    /// Generate a shared secret with someone elses public key (NIP-04 method)
    fn shared_secret_nip04(&self, other: &PublicKey) -> [u8; 32] {
        // Build the whole PublicKey from the XOnlyPublicKey
        let pubkey = secp256k1::PublicKey::from_x_only_public_key(
            other.as_xonly_public_key(),
            secp256k1::Parity::Even,
        );

        // Get the shared secret point without hashing
        let mut shared_secret_point: [u8; 64] =
            secp256k1::ecdh::shared_secret_point(&pubkey, &self.0);

        // Take the first 32 bytes
        let mut shared_key: [u8; 32] = [0; 32];
        shared_key.copy_from_slice(&shared_secret_point[..32]);

        // Zeroize what we aren't keeping
        shared_secret_point.zeroize();

        shared_key
    }

    /// Generate a shared secret with someone elses public key (NIP-44 method)
    fn shared_secret_nip44(&self, other: &PublicKey) -> [u8; 32] {
        // Build the whole PublicKey from the XOnlyPublicKey
        let pubkey = secp256k1::PublicKey::from_x_only_public_key(
            other.as_xonly_public_key(),
            secp256k1::Parity::Even,
        );

        let mut ssp = secp256k1::ecdh::shared_secret_point(&pubkey, &self.0)
            .as_slice()
            .to_owned();
        ssp.resize(32, 0); // keep only the X coordinate part

        let mut hasher = Sha256::new();
        hasher.update(ssp);
        let result = hasher.finalize();

        result.into()
    }

    /// Encrypt content via a shared secret according to NIP-04. Returns (IV, Ciphertext) pair.
    pub fn nip04_encrypt(
        &self,
        other: &PublicKey,
        plaintext: &[u8],
    ) -> Result<([u8; 16], Vec<u8>), Error> {
        let mut shared_secret = self.shared_secret_nip04(other);
        let iv = {
            let mut iv: [u8; 16] = [0; 16];
            OsRng.fill_bytes(&mut iv);
            iv
        };

        let ciphertext = cbc::Encryptor::<aes::Aes256>::new(&shared_secret.into(), &iv.into())
            .encrypt_padded_vec_mut::<Pkcs7>(plaintext);

        shared_secret.zeroize();

        Ok((iv, ciphertext))
    }

    /// Decrypt content via a shared secret according to NIP-04
    pub fn nip04_decrypt(
        &self,
        other: &PublicKey,
        ciphertext: &[u8],
        iv: [u8; 16],
    ) -> Result<Vec<u8>, Error> {
        let mut shared_secret = self.shared_secret_nip04(other);

        let plaintext = cbc::Decryptor::<aes::Aes256>::new(&shared_secret.into(), &iv.into())
            .decrypt_padded_vec_mut::<Pkcs7>(ciphertext)?;

        shared_secret.zeroize();

        Ok(plaintext)
    }

    /// Encrypt content via a shared secret according to NIP-44
    /// Only version 1 is currently supported.
    /// Always set forced_nonce=None (except for test vectors)
    pub fn nip44_encrypt(
        &self,
        other: &PublicKey,
        plaintext: &[u8],
        pad: bool,
        forced_nonce: Option<[u8; 24]>,
    ) -> String {
        use rand::Rng;
        let mut new_plaintext;

        let encrypt = |plaintext: &[u8]| -> String {
            use chacha20::cipher::StreamCipher;
            let mut shared_secret = self.shared_secret_nip44(other);
            let mut output: Vec<u8> = Vec::with_capacity(1 + 24 + plaintext.len());
            output.resize(1 + 24, 0);
            output[0] = 1; // Version
            match forced_nonce {
                Some(nonce) => output[1..=24].copy_from_slice(nonce.as_slice()),
                None => OsRng.fill_bytes(&mut output[1..=24]),
            }
            output.extend(plaintext); // Plaintext (will encrypt in place)
            let mut cipher = chacha20::XChaCha20::new(&shared_secret.into(), output[1..=24].into());
            shared_secret.zeroize();
            cipher.apply_keystream(&mut output[25..]);
            base64::engine::general_purpose::STANDARD.encode(output)
        };

        if pad {
            let end_plaintext = 4 + plaintext.len();

            // forced padding, up to a minimum of 32 bytes total so far (4 used for the u32 length)
            let forced_padding = if end_plaintext < 32 {
                32 - end_plaintext
            } else {
                0
            };
            let end_forced_padding = end_plaintext + forced_padding;

            // random length padding, up to 50% more
            let random_padding =
                OsRng.sample(rand::distributions::Uniform::new(0, end_forced_padding / 2));
            let end_random_padding = end_forced_padding + random_padding;

            // Make space
            new_plaintext = vec![0; end_random_padding];

            new_plaintext[0..4].copy_from_slice((plaintext.len() as u32).to_be_bytes().as_slice());
            new_plaintext[4..end_plaintext].copy_from_slice(plaintext);
            OsRng.fill_bytes(&mut new_plaintext[end_plaintext..]); // random padding

            let output = encrypt(&new_plaintext);
            new_plaintext.zeroize();
            output
        } else {
            encrypt(plaintext)
        }
    }

    /// Decrypt content via a shared secret according to NIP-44
    /// Only version 1 is currently supported.
    pub fn nip44_decrypt(
        &self,
        other: &PublicKey,
        ciphertext: &str,
        padded: bool,
    ) -> Result<Vec<u8>, Error> {
        use chacha20::cipher::StreamCipher;
        let mut shared_secret = self.shared_secret_nip44(other);
        let bytes = base64::engine::general_purpose::STANDARD.decode(ciphertext)?;
        if bytes[0] != 1 {
            return Err(Error::UnknownCipherVersion(bytes[0]));
        }
        let mut output: Vec<u8> = Vec::with_capacity(bytes[25..].len());
        output.extend(&bytes[25..]);

        let mut cipher = chacha20::XChaCha20::new(&shared_secret.into(), bytes[1..=24].into());
        shared_secret.zeroize();
        cipher.apply_keystream(&mut output);

        if padded {
            let len = u32::from_be_bytes(output[0..4].try_into().unwrap());
            if 4 + len as usize > output.len() {
                return Err(Error::OutOfRange(len as usize));
            }
            Ok(output[4..4 + len as usize].to_owned())
        } else {
            Ok(output)
        }
    }

    /// Export in a (non-portable) encrypted form. This does not downgrade
    /// the security of the key, but you are responsible to keep it encrypted.
    /// You should not attempt to decrypt it, only use `import_encrypted()` on
    /// it, or something similar in another library/client which also respects key
    /// security.
    ///
    /// This currently exports into EncryptedPrivateKey version 2.
    ///
    /// We recommend you zeroize() the password you pass in after you are
    /// done with it.
    pub fn export_encrypted(
        &self,
        password: &str,
        log2_rounds: u8,
    ) -> Result<EncryptedPrivateKey, Error> {
        // Generate a random 16-byte salt
        let salt = {
            let mut salt: [u8; 16] = [0; 16];
            OsRng.fill_bytes(&mut salt);
            salt
        };

        let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);

        let associated_data: Vec<u8> = {
            let key_security: u8 = match self.1 {
                KeySecurity::Weak => 0,
                KeySecurity::Medium => 1,
            };
            vec![key_security]
        };

        let ciphertext = {
            let cipher = {
                let symmetric_key = Self::password_to_key_v2(password, &salt, log2_rounds)?;
                XChaCha20Poly1305::new((&symmetric_key).into())
            };

            // The inner secret. We don't have to drop this because we are encrypting-in-place
            let mut inner_secret: Vec<u8> = self.0.secret_bytes().to_vec();

            let payload = Payload {
                msg: &inner_secret,
                aad: &associated_data,
            };

            let ciphertext = match cipher.encrypt(&nonce, payload) {
                Ok(c) => c,
                Err(_) => return Err(Error::Encryption),
            };

            inner_secret.zeroize();

            ciphertext
        };

        // Combine salt, IV and ciphertext
        let mut concatenation: Vec<u8> = Vec::new();
        concatenation.push(0x2); // 1 byte version number
        concatenation.push(log2_rounds); // 1 byte for scrypt N (rounds)
        concatenation.extend(salt); // 16 bytes of salt
        concatenation.extend(nonce); // 24 bytes of nonce
        concatenation.extend(associated_data); // 1 byte of key security
        concatenation.extend(ciphertext); // 48 bytes of ciphertext expected
                                          // Total length is 91 = 1 + 1 + 16 + 24 + 1 + 48

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
            // Versioned
            Self::import_encrypted_bech32(encrypted, password)
        } else {
            // Pre-versioned, deprecated
            Self::import_encrypted_base64(encrypted, password)
        }
    }

    // Current
    fn import_encrypted_bech32(
        encrypted: &EncryptedPrivateKey,
        password: &str,
    ) -> Result<PrivateKey, Error> {
        // bech32 decode
        let data = bech32::decode(&encrypted.0)?;
        if data.0 != "ncryptsec" {
            return Err(Error::WrongBech32("ncryptsec".to_string(), data.0));
        }
        let data = Vec::<u8>::from_base32(&data.1)?;
        match data[0] {
            1 => Self::import_encrypted_v1(data, password),
            2 => Self::import_encrypted_v2(data, password),
            _ => Err(Error::InvalidEncryptedPrivateKey),
        }
    }

    // current
    fn import_encrypted_v2(concatenation: Vec<u8>, password: &str) -> Result<PrivateKey, Error> {
        if concatenation.len() < 91 {
            return Err(Error::InvalidEncryptedPrivateKey);
        }

        // Break into parts
        let version: u8 = concatenation[0];
        assert_eq!(version, 2);
        let log2_rounds: u8 = concatenation[1];
        let salt: [u8; 16] = concatenation[2..2 + 16].try_into()?;
        let nonce = &concatenation[2 + 16..2 + 16 + 24];
        let associated_data = &concatenation[2 + 16 + 24..2 + 16 + 24 + 1];
        let ciphertext = &concatenation[2 + 16 + 24 + 1..];

        let cipher = {
            let symmetric_key = Self::password_to_key_v2(password, &salt, log2_rounds)?;
            XChaCha20Poly1305::new((&symmetric_key).into())
        };

        let payload = Payload {
            msg: ciphertext,
            aad: associated_data,
        };

        let mut inner_secret = match cipher.decrypt(nonce.into(), payload) {
            Ok(is) => is,
            Err(_) => return Err(Error::Encryption),
        };

        if associated_data.is_empty() {
            return Err(Error::InvalidEncryptedPrivateKey);
        }
        let key_security = match associated_data[0] {
            0 => KeySecurity::Weak,
            1 => KeySecurity::Medium,
            _ => return Err(Error::InvalidEncryptedPrivateKey),
        };

        let signing_key = secp256k1::SecretKey::from_slice(&inner_secret)?;
        inner_secret.zeroize();

        Ok(PrivateKey(signing_key, key_security))
    }

    // deprecated
    fn import_encrypted_base64(
        encrypted: &EncryptedPrivateKey,
        password: &str,
    ) -> Result<PrivateKey, Error> {
        let concatenation = base64::engine::general_purpose::STANDARD.decode(&encrypted.0)?; // 64 or 80 bytes
        if concatenation.len() == 64 {
            Self::import_encrypted_pre_v1(concatenation, password)
        } else if concatenation.len() == 80 {
            Self::import_encrypted_v1(concatenation, password)
        } else {
            Err(Error::InvalidEncryptedPrivateKey)
        }
    }

    // deprecated
    fn import_encrypted_v1(concatenation: Vec<u8>, password: &str) -> Result<PrivateKey, Error> {
        // Break into parts
        let salt: [u8; 16] = concatenation[..16].try_into()?;
        let iv: [u8; 16] = concatenation[16..32].try_into()?;
        let ciphertext = &concatenation[32..]; // 48 bytes

        let key = Self::password_to_key_v1(password, &salt, V1_HMAC_ROUNDS)?;

        // AES-256-CBC decrypt
        let mut plaintext = cbc::Decryptor::<aes::Aes256>::new(&key.into(), &iv.into())
            .decrypt_padded_vec_mut::<Pkcs7>(ciphertext)?; // 44 bytes
        if plaintext.len() != 44 {
            return Err(Error::InvalidEncryptedPrivateKey);
            //return Err(Error::AssertionFailed("Import encrypted plaintext len != 44".to_owned()));
        }

        // Verify the check value
        if plaintext[plaintext.len() - 12..plaintext.len() - 1] != V1_CHECK_VALUE {
            return Err(Error::WrongDecryptionPassword);
        }

        // Get the key security
        let ks = KeySecurity::try_from(plaintext[plaintext.len() - 1])?;
        let output = PrivateKey(
            secp256k1::SecretKey::from_slice(&plaintext[..plaintext.len() - 12])?,
            ks,
        );

        // Here we zeroize plaintext:
        plaintext.zeroize();

        Ok(output)
    }

    // deprecated
    fn import_encrypted_pre_v1(
        iv_plus_ciphertext: Vec<u8>,
        password: &str,
    ) -> Result<PrivateKey, Error> {
        let key = Self::password_to_key_v1(password, b"nostr", 4096)?;

        if iv_plus_ciphertext.len() < 48 {
            // Should be 64 from padding, but we pushed in 48
            return Err(Error::InvalidEncryptedPrivateKey);
        }

        // Pull the IV off
        let iv: [u8; 16] = iv_plus_ciphertext[..16].try_into()?;
        let ciphertext = &iv_plus_ciphertext[16..]; // 64 bytes

        // AES-256-CBC decrypt
        let mut pt = cbc::Decryptor::<aes::Aes256>::new(&key.into(), &iv.into())
            .decrypt_padded_vec_mut::<Pkcs7>(ciphertext)?; // 48 bytes

        // Verify the check value
        if pt[pt.len() - 12..pt.len() - 1] != V1_CHECK_VALUE {
            return Err(Error::WrongDecryptionPassword);
        }

        // Get the key security
        let ks = KeySecurity::try_from(pt[pt.len() - 1])?;
        let output = PrivateKey(secp256k1::SecretKey::from_slice(&pt[..pt.len() - 12])?, ks);

        // Here we zeroize pt:
        pt.zeroize();

        Ok(output)
    }

    // Hash/Stretch password with pbkdf2 into a 32-byte (256-bit) key
    fn password_to_key_v1(password: &str, salt: &[u8], rounds: u32) -> Result<[u8; 32], Error> {
        let mut key: [u8; 32] = [0; 32];
        pbkdf2::<Hmac<Sha256>>(password.as_bytes(), salt, rounds, &mut key)?;
        Ok(key)
    }

    // Hash/Stretch password with scrypt into a 32-byte (256-bit) key
    fn password_to_key_v2(password: &str, salt: &[u8; 16], log_n: u8) -> Result<[u8; 32], Error> {
        let params = match scrypt::Params::new(log_n, 8, 1, 32) {
            // r=8, p=1
            Ok(p) => p,
            Err(_) => return Err(Error::Scrypt),
        };
        let mut key: [u8; 32] = [0; 32];
        if scrypt::scrypt(password.as_bytes(), salt, &params, &mut key).is_err() {
            return Err(Error::Scrypt);
        }
        Ok(key)
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
    fn test_export_import() {
        let pk = PrivateKey::generate();
        // we use a low log_n here because this is run slowly in debug mode
        let exported = pk.export_encrypted("secret", 13).unwrap();
        println!("{exported}");
        let imported_pk = PrivateKey::import_encrypted(&exported, "secret").unwrap();

        // Be sure the keys generate identical public keys
        assert_eq!(pk.public_key(), imported_pk.public_key());

        // Be sure the security level is still Medium
        assert_eq!(pk.key_security(), KeySecurity::Medium)
    }

    #[test]
    fn test_import_old_formats() {
        let decrypted = "a28129ab0b70c8d5e75aaf510ec00bff47fde7ca4ab9e3d9315c77edc86f037f";

        // pre-salt base64 (-2?)
        let encrypted = EncryptedPrivateKey("F+VYIvTCtIZn4c6owPMZyu4Zn5DH9T5XcgZWmFG/3ma4C3PazTTQxQcIF+G+daeFlkqsZiNIh9bcmZ5pfdRPyg==".to_owned());
        assert_eq!(
            encrypted.decrypt("nostr").unwrap().as_hex_string(),
            decrypted
        );

        // Version -1: post-salt base64
        let encrypted = EncryptedPrivateKey("AZQYNwAGULWyKweTtw6WCljV+1cil8IMRxfZ7Rs3nCfwbVQBV56U6eV9ps3S1wU7ieCx6EraY9Uqdsw71TY5Yv/Ep6yGcy9m1h4YozuxWQE=".to_owned());
        assert_eq!(
            encrypted.decrypt("nostr").unwrap().as_hex_string(),
            decrypted
        );

        let decrypted = "3501454135014541350145413501453fefb02227e449e57cf4d3a3ce05378683";

        // Version -1
        let encrypted = EncryptedPrivateKey("KlmfCiO+Tf8A/8bm/t+sXWdb1Op4IORdghC7n/9uk/vgJXIcyW7PBAx1/K834azuVmQnCzGq1pmFMF9rNPWQ9Q==".to_owned());
        assert_eq!(
            encrypted.decrypt("nostr").unwrap().as_hex_string(),
            decrypted
        );

        // Version 0:
        let encrypted = EncryptedPrivateKey("AZ/2MU2igqP0keoW08Z/rxm+/3QYcZn3oNbVhY6DSUxSDkibNp+bFN/WsRQxP7yBKwyEJVu/YSBtm2PI9DawbYOfXDqfmpA3NTPavgXwUrw=".to_owned());
        assert_eq!(
            encrypted.decrypt("nostr").unwrap().as_hex_string(),
            decrypted
        );

        // Version 1:
        let encrypted = EncryptedPrivateKey("ncryptsec1q9hnc06cs5tuk7znrxmetj4q9q2mjtccg995kp86jf3dsp3jykv4fhak730wds4s0mja6c9v2fvdr5dhzrstds8yks5j9ukvh25ydg6xtve6qvp90j0c8a2s5tv4xn7kvulg88".to_owned());
        assert_eq!(
            encrypted.decrypt("nostr").unwrap().as_hex_string(),
            decrypted
        );

        // Version 2:
        let encrypted = EncryptedPrivateKey("ncryptsec1qgg9947rlpvqu76pj5ecreduf9jxhselq2nae2kghhvd5g7dgjtcxfqtd67p9m0w57lspw8gsq6yphnm8623nsl8xn9j4jdzz84zm3frztj3z7s35vpzmqf6ksu8r89qk5z2zxfmu5gv8th8wclt0h4p".to_owned());
        assert_eq!(
            encrypted.decrypt("nostr").unwrap().as_hex_string(),
            decrypted
        );
    }

    #[test]
    fn test_privkey_bech32() {
        let mut pk = PrivateKey::mock();

        let encoded = pk.as_bech32_string();
        println!("bech32: {encoded}");

        let decoded = PrivateKey::try_from_bech32_string(&encoded).unwrap();

        assert_eq!(pk.0.secret_bytes(), decoded.0.secret_bytes());
        assert_eq!(decoded.1, KeySecurity::Weak);
    }

    #[test]
    fn test_privkey_nip04() {
        let private_key = PrivateKey::mock();
        let other_public_key = PublicKey::mock();

        let message = "hello world, this should come out just dandy.".as_bytes();
        let (iv, encrypted) = private_key
            .nip04_encrypt(&other_public_key, message)
            .unwrap();
        let decrypted = private_key
            .nip04_decrypt(&other_public_key, &encrypted, iv)
            .unwrap();

        assert_eq!(message, decrypted);
    }

    #[test]
    fn test_privkey_nip44() {
        struct TestVector {
            sec1: &'static str,
            sec2: Option<&'static str>,
            pub2: Option<&'static str>,
            shared: Option<&'static str>,
            nonce: Option<&'static str>,
            plaintext: Option<Vec<u8>>,
            ciphertext: Option<&'static str>,
            note: &'static str,
            fail: bool,
        }

        impl Default for TestVector {
            fn default() -> TestVector {
                TestVector {
                    sec1: "0000000000000000000000000000000000000000000000000000000000000001",
                    sec2: None,
                    pub2: None,
                    shared: None,
                    nonce: None,
                    plaintext: None,
                    ciphertext: None,
                    note: "none",
                    fail: false,
                }
            }
        }

        let vectors: Vec<TestVector> = vec![
            TestVector {
                sec1: "0000000000000000000000000000000000000000000000000000000000000001",
                sec2: Some("0000000000000000000000000000000000000000000000000000000000000002"),
                shared: Some("0135da2f8acf7b9e3090939432e47684eb888ea38c2173054d4eedffdf152ca5"),
                nonce: Some("121f9d60726777642fd82286791ab4d7461c9502ebcbb6e6"),
                plaintext: Some(b"a".to_vec()),
                ciphertext: Some("ARIfnWByZ3dkL9gihnkatNdGHJUC68u25qM="),
                note: "sk1 = 1, sk2 = random, 0x02",
                .. Default::default()
            },
            TestVector {
                sec1: "0000000000000000000000000000000000000000000000000000000000000002",
                sec2: Some("0000000000000000000000000000000000000000000000000000000000000001"),
                shared: Some("0135da2f8acf7b9e3090939432e47684eb888ea38c2173054d4eedffdf152ca5"),
                plaintext: Some(b"a".to_vec()),
                ciphertext: Some("AeCt7jJ8L+WBOTiCSfeXEGXB/C/wgsrSRek="),
                nonce: Some("e0adee327c2fe58139388249f7971065c1fc2ff082cad245"),
                note: "sk1 = 1, sk2 = random, 0x02",
                .. Default::default()
            },
            TestVector {
                sec1: "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364139",
                pub2: Some("0000000000000000000000000000000000000000000000000000000000000002"),
                shared: Some("a6d6a2f7011cdd1aeef325948f48c6efa40f0ec723ae7f5ac7e3889c43481500"),
                nonce: Some("f481750e13dfa90b722b7cce0db39d80b0db2e895cc3001a"),
                plaintext: Some(b"a".to_vec()),
                ciphertext: Some("AfSBdQ4T36kLcit8zg2znYCw2y6JXMMAGjM="),
                note: "sec1 = n-2, pub2: random, 0x02",
                .. Default::default()
            },
            TestVector {
                sec1: "0000000000000000000000000000000000000000000000000000000000000002",
                pub2: Some("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdeb"),
                shared: Some("4908464f77dd74e11a9b4e4a3bc2467445bd794e8abcbfafb65a6874f9e25a8f"),
                nonce: Some("45c484ba2c0397853183adba6922156e09a2ad4e3e6914f2"),
                plaintext: Some(b"A Peer-to-Peer Electronic Cash System".to_vec()),
                ciphertext: Some("AUXEhLosA5eFMYOtumkiFW4Joq1OPmkU8k/25+3+VDFvOU39qkUDl1aiy8Q+0ozTwbhD57VJoIYayYS++hE="),
                note: "sec1 = 2, pub2: ",
                .. Default::default()
            },
            TestVector {
                sec1: "0000000000000000000000000000000000000000000000000000000000000001",
                pub2: Some("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"),
                shared: Some("132f39a98c31baaddba6525f5d43f2954472097fa15265f45130bfdb70e51def"),
                nonce: Some("d60de08405cf9bde508147e82224ac6af409c12b9e5492e1"),
                plaintext: Some(b"A purely peer-to-peer version of electronic cash would allow online payments to be sent directly from one party to another without going through a financial institution. Digital signatures provide part of the solution, but the main benefits are lost if a trusted third party is still required to prevent double-spending.".to_vec()),
                ciphertext: Some("AdYN4IQFz5veUIFH6CIkrGr0CcErnlSS4VdvoQaP2DCB1dIFL72HSriG1aFABcTlu86hrsG0MdOO9rPdVXc3jptMMzqvIN6tJlHPC8GdwFD5Y8BT76xIIOTJR2W0IdrM7++WC/9harEJAdeWHDAC9zNJX81CpCz4fnV1FZ8GxGLC0nUF7NLeUiNYu5WFXQuO9uWMK0pC7tk3XVogk90X6rwq0MQG9ihT7e1elatDy2YGat+VgQlDrz8ZLRw/lvU+QqeXMQgjqn42sMTrimG6NdKfHJSVWkT6SKZYVsuTyU1Iu5Nk0twEV8d11/MPfsMx4i36arzTC9qxE6jftpOoG8f/jwPTSCEpHdZzrb/CHJcpc+zyOW9BZE2ZOmSxYHAE0ustC9zRNbMT3m6LqxIoHq8j+8Ysu+Cwqr4nUNLYq/Q31UMdDg1oamYS17mWIAS7uf2yF5uT5IlG"),
                note: "sec1 == pub2",
                .. Default::default()
            },
            TestVector {
                sec1: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                pub2: Some("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"),
                plaintext: Some(b"a".to_vec()),
                note: "sec1 higher than curve.n",
                fail: true,
                .. Default::default()
            },
            TestVector {
                sec1: "0000000000000000000000000000000000000000000000000000000000000000",
                pub2: Some("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"),
                plaintext: Some(b"a".to_vec()),
                note: "sec1 is 0",
                fail: true,
                .. Default::default()
            },
            TestVector {
                sec1: "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364139",
                pub2: Some("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
                plaintext: Some(b"a".to_vec()),
                note: "pub2 is invalid, no sqrt, all-ff",
                fail: true,
                .. Default::default()
            },
            TestVector {
                sec1: "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
                pub2: Some("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"),
                plaintext: Some(b"a".to_vec()),
                note: "sec1 == curve.n",
                fail: true,
                .. Default::default()
            },
            TestVector {
                sec1: "0000000000000000000000000000000000000000000000000000000000000002",
                pub2: Some("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"),
                plaintext: Some(b"a".to_vec()),
                note: "pub2 is invalid, no sqrt",
                fail: true,
                .. Default::default()
            },
        ];

        for (num, vector) in vectors.iter().enumerate() {
            let mut sec1 = match PrivateKey::try_from_hex_string(vector.sec1) {
                Ok(key) => key,
                Err(_) => {
                    if vector.fail {
                        continue;
                    } else {
                        panic!("Test vector {} failed on sec1: {}", num, vector.note);
                    }
                }
            };
            println!("sec1: {}", sec1.as_hex_string());

            let pub2 = {
                if let Some(sec2) = vector.sec2 {
                    let sec2 = match PrivateKey::try_from_hex_string(sec2) {
                        Ok(priv_key) => priv_key,
                        Err(_) => {
                            if vector.fail {
                                continue;
                            } else {
                                panic!("Test vector {} failed on sec2: {}", num, vector.note);
                            }
                        }
                    };
                    sec2.public_key()
                } else if let Some(pub2) = vector.pub2 {
                    match PublicKey::try_from_hex_string(pub2, true) {
                        Ok(pub_key) => pub_key,
                        Err(_) => {
                            if vector.fail {
                                continue;
                            } else {
                                panic!("Test vector {} failed on pub2: {}", num, vector.note);
                            }
                        }
                    }
                } else {
                    panic!("Test vector {} has no sec2 or pub2: {}", num, vector.note);
                }
            };
            println!("pub2: {}", pub2.as_hex_string());

            // Test shared vector
            let shared = sec1.shared_secret_nip44(&pub2);
            let shared_hex = hex::encode(shared);
            if let Some(s) = vector.shared {
                if s != shared_hex {
                    panic!(
                        "Test vector {} shared point mismatch: {}\ntheirs: {}\nours:   {}",
                        num, vector.note, s, shared_hex
                    );
                } else {
                    println!("Test vector {} shared point is good", num);
                }
            }

            // Test Encrypting
            if let (Some(plaintext), Some(ciphertext), Some(noncestr)) =
                (&vector.plaintext, vector.ciphertext, vector.nonce)
            {
                let nonce: [u8; 24] = hex::decode(noncestr).unwrap().try_into().unwrap();
                let ciphertext2 = sec1.nip44_encrypt(&pub2, &plaintext, false, Some(nonce));
                assert_eq!(ciphertext, ciphertext2);
                println!("Test vector {} encryption matches", num);
            }

            // Test Decrypting
            if let (Some(plaintext), Some(ciphertext), Some(sec2)) =
                (&vector.plaintext, vector.ciphertext, vector.sec2)
            {
                let sec2 = match PrivateKey::try_from_hex_string(sec2) {
                    Ok(key) => key,
                    Err(_) => {
                        if vector.fail {
                            continue;
                        } else {
                            panic!("Test vector {} failed on sec1: {}", num, vector.note);
                        }
                    }
                };
                let pub1 = sec1.public_key();

                let plaintext2 = sec2.nip44_decrypt(&pub1, ciphertext, false).unwrap();
                assert_eq!(plaintext, &plaintext2);
                println!("Test vector {} decryption matches", num);
            }
        }
    }

    #[test]
    fn test_privkey_nip44_pad() {
        let sec1 = PrivateKey::try_from_hex_string(
            "0000000000000000000000000000000000000000000000000000000000000001",
        )
        .unwrap();

        let sec2 = PrivateKey::try_from_hex_string(
            "0000000000000000000000000000000000000000000000000000000000000002",
        )
        .unwrap();

        let plaintext = "yes".as_bytes();

        let ciphertext = sec1.nip44_encrypt(&sec2.public_key(), plaintext, true, None);
        assert!(ciphertext.len() >= 32);

        let plaintext2 = sec2
            .nip44_decrypt(&sec1.public_key(), &ciphertext, true)
            .unwrap();
        assert_eq!(plaintext, plaintext2);
    }
}

/*
 * version -1 (if 64 bytes, base64 encoded)
 *
 *    symmetric_aes_key = pbkdf2_hmac_sha256(password,  salt="nostr", rounds=4096)
 *    pre_encoded_encrypted_private_key = AES-256-CBC(IV=random, key=symmetric_aes_key, data=private_key)
 *    encrypted_private_key = base64(concat(IV, pre_encoded_encrypted_private_key))
 *
 * version 0 (80 bytes, base64 encoded, same as v1 internally)
 *
 *    symmetric_aes_key = pbkdf2_hmac_sha256(password,  salt=concat(0x1, 15 random bytes), rounds=100000)
 *    key_security_byte = 0x0 if weak, 0x1 if medium
 *    inner_concatenation = concat(
 *        private_key,                                         // 32 bytes
 *        [15, 91, 241, 148, 90, 143, 101, 12, 172, 255, 103], // 11 bytes
 *        key_security_byte                                    //  1 byte
 *    )
 *    pre_encoded_encrypted_private_key = AES-256-CBC(IV=random, key=symmetric_aes_key, data=private_key)
 *    outer_concatenation = concat(IV, pre_encoded_encrypted_private_key)
 *    encrypted_private_key = base64(outer_concatenation)
 *
 * version 1
 *
 *    salt = concat(byte(0x1), 15 random bytes)
 *    symmetric_aes_key = pbkdf2_hmac_sha256(password, salt=salt, rounds=100,000)
 *    key_security_byte = 0x0 if weak, 0x1 if medium
 *    inner_concatenation = concat(
 *        private_key,                                          // 32 bytes
 *        [15, 91, 241, 148, 90, 143, 101, 12, 172, 255, 103],  // 11 bytes
 *        key_security_byte                                     //  1 byte
 *    )
 *    pre_encoded_encrypted_private_key = AES-256-CBC(IV=random, key=symmetric_aes_key, data=private_key)
 *    outer_concatenation = concat(salt, IV, pre_encoded_encrypted_private_key)
 *    encrypted_private_key = bech32('ncryptsec', outer_concatenation)
 *
 * version 2 (scrypt, xchacha20-poly1305)
 *
 *    rounds = user selected power of 2
 *    salt = 16 random bytes
 *    symmetric_key = scrypt(password, salt=salt, r=8, p=1, N=rounds)
 *    key_security_byte = 0x0 if weak, 0x1 if medium, 0x2 if not implemented
 *    nonce = 12 random bytes
 *    pre_encoded_encrypted_private_key = xchacha20-poly1305(
 *        plaintext=private_key, nonce=nonce, key=symmetric_key,
 *        associated_data=key_security_byte
 *    )
 *    version = byte(0x3)
 *    outer_concatenation = concat(version, log2(rounds) as one byte, salt, nonce, pre_encoded_encrypted_private_key)
 *    encrypted_private_key = bech32('ncryptsec', outer_concatenation)
 */
