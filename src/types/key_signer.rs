use crate::{
    ContentEncryptionAlgorithm, EncryptedPrivateKey, Error, Id, KeySecurity, PrivateKey, PublicKey,
    Signature, Signer,
};
use std::fmt;

/// Signer with a local private key (and public key)
pub struct KeySigner {
    encrypted_private_key: EncryptedPrivateKey,
    public_key: PublicKey,
    private_key: Option<PrivateKey>,
}

impl fmt::Debug for KeySigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        f.debug_struct("KeySigner")
            .field("encrypted_private_key", &self.encrypted_private_key)
            .field("public_key", &self.public_key)
            .finish()
    }
}

impl KeySigner {
    /// Create a Signer from an `EncryptedPrivateKey`
    pub fn from_locked_parts(epk: EncryptedPrivateKey, pk: PublicKey) -> Self {
        Self {
            encrypted_private_key: epk,
            public_key: pk,
            private_key: None,
        }
    }

    /// Create a Signer from a `PrivateKey`
    pub fn from_private_key(privk: PrivateKey, password: &str, log_n: u8) -> Result<Self, Error> {
        let epk = privk.export_encrypted(password, log_n)?;
        Ok(Self {
            encrypted_private_key: epk,
            public_key: privk.public_key(),
            private_key: Some(privk),
        })
    }

    /// Create a Signer from an `EncryptedPrivateKey` and a password to unlock it
    pub fn from_encrypted_private_key(epk: EncryptedPrivateKey, pass: &str) -> Result<Self, Error> {
        let priv_key = epk.decrypt(pass)?;
        let pub_key = priv_key.public_key();
        Ok(Self::from_locked_parts(epk, pub_key))
    }

    /// Create a Signer by generating a new `PrivateKey`
    pub fn generate(password: &str, log_n: u8) -> Result<Self, Error> {
        let privk = PrivateKey::generate();
        let epk = privk.export_encrypted(password, log_n)?;
        Ok(Self {
            encrypted_private_key: epk,
            public_key: privk.public_key(),
            private_key: Some(privk),
        })
    }
}

impl Signer for KeySigner {
    fn is_locked(&self) -> bool {
        self.private_key.is_none()
    }

    fn unlock(&mut self, password: &str) -> Result<(), Error> {
        if !self.is_locked() {
            return Ok(());
        }

        let private_key = match self.encrypted_private_key.decrypt(password) {
            Ok(pk) => pk,
            Err(e) => return Err(e),
        };

        self.private_key = Some(private_key);

        Ok(())
    }

    fn lock(&mut self) {
        self.private_key = None;
    }

    fn change_passphrase(&mut self, old: &str, new: &str, log_n: u8) -> Result<(), Error> {
        let private_key = self.encrypted_private_key.decrypt(old)?;
        self.encrypted_private_key = private_key.export_encrypted(new, log_n)?;
        self.private_key = Some(private_key);
        Ok(())
    }

    fn upgrade(&mut self, pass: &str, log_n: u8) -> Result<(), Error> {
        let private_key = self.encrypted_private_key.decrypt(pass)?;
        self.encrypted_private_key = private_key.export_encrypted(pass, log_n)?;
        Ok(())
    }

    fn public_key(&self) -> PublicKey {
        self.public_key
    }

    fn encrypted_private_key(&self) -> Option<&EncryptedPrivateKey> {
        Some(&self.encrypted_private_key)
    }

    fn sign_id(&self, id: Id) -> Result<Signature, Error> {
        match &self.private_key {
            Some(pk) => pk.sign_id(id),
            None => Err(Error::SignerIsLocked),
        }
    }

    fn sign(&self, message: &[u8]) -> Result<Signature, Error> {
        match &self.private_key {
            Some(pk) => pk.sign(message),
            None => Err(Error::SignerIsLocked),
        }
    }

    fn encrypt(
        &self,
        other: &PublicKey,
        plaintext: &str,
        algo: ContentEncryptionAlgorithm,
    ) -> Result<String, Error> {
        match &self.private_key {
            Some(pk) => pk.encrypt(other, plaintext, algo),
            None => Err(Error::SignerIsLocked),
        }
    }

    fn decrypt_nip44(&self, other: &PublicKey, ciphertext: &str) -> Result<String, Error> {
        match &self.private_key {
            Some(pk) => pk.decrypt_nip44(other, ciphertext),
            None => Err(Error::SignerIsLocked),
        }
    }

    fn decrypt_nip04(&self, other: &PublicKey, ciphertext: &str) -> Result<Vec<u8>, Error> {
        match &self.private_key {
            Some(pk) => pk.decrypt_nip04(other, ciphertext),
            None => Err(Error::SignerIsLocked),
        }
    }

    fn nip44_conversation_key(&self, other: &PublicKey) -> Result<[u8; 32], Error> {
        let xpub = other.as_xonly_public_key();
        match &self.private_key {
            Some(pk) => Ok(nip44::get_conversation_key(pk.as_secret_key(), xpub)),
            None => Err(Error::SignerIsLocked),
        }
    }

    fn export_private_key_in_hex(
        &mut self,
        pass: &str,
        log_n: u8,
    ) -> Result<(String, bool), Error> {
        if let Some(pk) = &mut self.private_key {
            // Test password and check key security
            let pkcheck = self.encrypted_private_key.decrypt(pass)?;

            // side effect: this may downgrade the key security of self.private_key
            let output = pk.as_hex_string();

            // If key security changed, re-export
            let mut downgraded = false;
            if pk.key_security() != pkcheck.key_security() {
                downgraded = true;
                self.encrypted_private_key = pk.export_encrypted(pass, log_n)?;
            }
            Ok((output, downgraded))
        } else {
            Err(Error::SignerIsLocked)
        }
    }

    fn export_private_key_in_bech32(
        &mut self,
        pass: &str,
        log_n: u8,
    ) -> Result<(String, bool), Error> {
        if let Some(pk) = &mut self.private_key {
            // Test password and check key security
            let pkcheck = self.encrypted_private_key.decrypt(pass)?;

            // side effect: this may downgrade the key security of self.private_key
            let output = pk.as_bech32_string();

            // If key security changed, re-export
            let mut downgraded = false;
            if pk.key_security() != pkcheck.key_security() {
                downgraded = true;
                self.encrypted_private_key = pk.export_encrypted(pass, log_n)?;
            }

            Ok((output, downgraded))
        } else {
            Err(Error::SignerIsLocked)
        }
    }

    fn key_security(&self) -> Result<KeySecurity, Error> {
        match &self.private_key {
            Some(pk) => Ok(pk.key_security()),
            None => Err(Error::SignerIsLocked),
        }
    }
}
