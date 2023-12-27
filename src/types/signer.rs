use crate::{
    ContentEncryptionAlgorithm, EncryptedPrivateKey, Error, Id, KeySecurity, PrivateKey, PublicKey,
    Signature,
};
use std::fmt;

/// Signer with a locked local key (and public key)
#[derive(Debug)]
#[allow(dead_code)]
pub struct LockedKeyState {
    encrypted_private_key: EncryptedPrivateKey,
    public_key: PublicKey,
}

/// Signer with an unlocked local key
#[allow(dead_code)]
pub struct UnlockedKeyState {
    encrypted_private_key: EncryptedPrivateKey,
    public_key: PublicKey,
    private_key: PrivateKey,
}

impl fmt::Debug for UnlockedKeyState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        f.debug_struct("UnlockedKeyState")
            .field("encrypted_private_key", &self.encrypted_private_key)
            .field("public_key", &self.public_key)
            .finish()
    }
}

mod sealed {
    pub trait Sealed {}
    impl Sealed for super::LockedKeyState {}
    impl Sealed for super::UnlockedKeyState {}
}

/// The state of the Signer
pub trait SignerState: sealed::Sealed {
    /// Is the signer locked?
    fn locked(&self) -> bool;

    /// What is the signer's public key?
    fn public_key(&self) -> PublicKey;

    /// What is the signer's encrypted private key?
    fn encrypted_private_key(&self) -> Option<&EncryptedPrivateKey>;
}

impl SignerState for LockedKeyState {
    fn locked(&self) -> bool {
        true
    }
    fn public_key(&self) -> PublicKey {
        self.public_key
    }
    fn encrypted_private_key(&self) -> Option<&EncryptedPrivateKey> {
        Some(&self.encrypted_private_key)
    }
}
impl SignerState for UnlockedKeyState {
    fn locked(&self) -> bool {
        false
    }
    fn public_key(&self) -> PublicKey {
        self.public_key
    }
    fn encrypted_private_key(&self) -> Option<&EncryptedPrivateKey> {
        Some(&self.encrypted_private_key)
    }
}

/// Trait and operations that an unlocked signer can perform
pub trait UnlockedSigner {
    /// Sign a 32-bit hash
    fn sign_id(&self, id: Id) -> Result<Signature, Error>;

    /// Sign a message (this hashes with SHA-256 first internally)
    fn sign(&self, message: &[u8]) -> Result<Signature, Error>;

    /// Encrypt
    fn encrypt(
        &self,
        other: &PublicKey,
        plaintext: &str,
        algo: ContentEncryptionAlgorithm,
    ) -> Result<String, Error>;

    /// Decrypt NIP-44
    fn decrypt_nip44(&self, other: &PublicKey, ciphertext: &str) -> Result<String, Error>;

    /// Decrypt NIP-04
    fn decrypt_nip04(&self, other: &PublicKey, ciphertext: &str) -> Result<Vec<u8>, Error>;
}

/// A signer
#[allow(dead_code)]
#[derive(Debug)]
pub struct Signer<S: SignerState> {
    state: S,
}

/// Build a new signer
#[derive(Debug, Copy, Clone)]
pub struct SignerBuilder;

impl SignerBuilder {
    /// Create a Signer from an `EncryptedPrivateKey`
    pub fn new_from_locked_parts(
        epk: EncryptedPrivateKey,
        pk: PublicKey,
    ) -> Signer<LockedKeyState> {
        Signer {
            state: LockedKeyState {
                encrypted_private_key: epk,
                public_key: pk,
            },
        }
    }

    /// Create a Signer from a `PrivateKey`
    pub fn new_from_private_key(
        privk: PrivateKey,
        password: &str,
        log_n: u8,
    ) -> Result<Signer<UnlockedKeyState>, Error> {
        let epk = privk.export_encrypted(password, log_n)?;
        Ok(Signer {
            state: UnlockedKeyState {
                encrypted_private_key: epk,
                public_key: privk.public_key(),
                private_key: privk,
            },
        })
    }

    /// Create a Signer by generating a new `PrivateKey`
    pub fn generate(password: &str, log_n: u8) -> Result<Signer<UnlockedKeyState>, Error> {
        let privk = PrivateKey::generate();
        let epk = privk.export_encrypted(password, log_n)?;
        Ok(Signer {
            state: UnlockedKeyState {
                encrypted_private_key: epk,
                public_key: privk.public_key(),
                private_key: privk,
            },
        })
    }
}

impl<S: SignerState> Signer<S> {
    /// Is the private key locked?
    #[inline]
    pub fn locked(&self) -> bool {
        self.state.locked()
    }

    /// The public key
    #[inline]
    pub fn public_key(&self) -> PublicKey {
        self.state.public_key()
    }

    /// The encrypted private key
    #[inline]
    pub fn encrypted_private_key(&self) -> Option<&EncryptedPrivateKey> {
        self.state.encrypted_private_key()
    }
}

impl Signer<LockedKeyState> {
    /// Try to unlock the encrypted private key
    pub fn unlock(self, password: &str) -> Result<Signer<UnlockedKeyState>, (Self, Error)> {
        let private_key = match self.state.encrypted_private_key.decrypt(password) {
            Ok(pk) => pk,
            Err(e) => return Err((self, e)),
        };

        Ok(Signer {
            state: UnlockedKeyState {
                encrypted_private_key: self.state.encrypted_private_key,
                public_key: private_key.public_key(),
                private_key,
            },
        })
    }

    /// Change the passphrase
    pub fn change_passphrase(
        self,
        old: &str,
        new: &str,
        log_n: u8,
    ) -> Result<Signer<UnlockedKeyState>, Error> {
        // Test old password first
        let private_key = self.state.encrypted_private_key.decrypt(old)?;
        let encrypted_private_key = private_key.export_encrypted(new, log_n)?;
        Ok(Signer {
            state: UnlockedKeyState {
                encrypted_private_key,
                public_key: private_key.public_key(),
                private_key,
            },
        })
    }
}

impl Signer<UnlockedKeyState> {
    /// Lock the private key
    pub fn lock(self) -> Signer<LockedKeyState> {
        Signer {
            state: LockedKeyState {
                encrypted_private_key: self.state.encrypted_private_key,
                public_key: self.state.public_key,
            },
        }
    }

    /// Get the security level of the private key
    pub fn key_security(&self) -> KeySecurity {
        self.state.private_key.key_security()
    }

    /// Change the passphrase
    pub fn change_passphrase(&mut self, old: &str, new: &str, log_n: u8) -> Result<(), Error> {
        // Test old password first
        let _ = self.state.encrypted_private_key.decrypt(old)?;
        self.state.encrypted_private_key = self.state.private_key.export_encrypted(new, log_n)?;
        Ok(())
    }

    /// Export the private key in hex.
    ///
    /// This returns a boolean indicating if the key security was downgraded. If it was,
    /// the caller should save the new self.encrypted_private_key()
    ///
    /// We need the password and log_n parameters to possibly rebuild
    /// the EncryptedPrivateKey when downgrading key security
    pub fn export_private_key_in_hex(
        &mut self,
        pass: &str,
        log_n: u8,
    ) -> Result<(String, bool), Error> {
        // side effect: this may downgrade the key security of self.private_key
        let output = self.state.private_key.as_hex_string();

        // Test password and check key security
        let pk = self.state.encrypted_private_key.decrypt(pass)?;

        // If key security changed, re-export
        let mut downgraded = false;
        if self.state.private_key.key_security() != pk.key_security() {
            downgraded = true;
            self.state.encrypted_private_key =
                self.state.private_key.export_encrypted(pass, log_n)?;
        }

        Ok((output, downgraded))
    }

    /// Export the private key in bech32.
    ///
    /// This returns a boolean indicating if the key security was downgraded. If it was,
    /// the caller should save the new self.encrypted_private_key()
    ///
    /// We need the password and log_n parameters to possibly rebuild
    /// the EncryptedPrivateKey when downgrading key security
    pub fn export_private_key_in_bech32(
        &mut self,
        pass: &str,
        log_n: u8,
    ) -> Result<(String, bool), Error> {
        // side effect: this may downgrade the key security of self.private_key
        let output = self.state.private_key.as_bech32_string();

        // Test password and check key security
        let pk = self.state.encrypted_private_key.decrypt(pass)?;

        // If key security changed, re-export
        let mut downgraded = false;
        if self.state.private_key.key_security() != pk.key_security() {
            downgraded = true;
            self.state.encrypted_private_key =
                self.state.private_key.export_encrypted(pass, log_n)?;
        }

        Ok((output, downgraded))
    }
}

impl UnlockedSigner for Signer<UnlockedKeyState> {
    fn sign_id(&self, id: Id) -> Result<Signature, Error> {
        self.state.private_key.sign_id(id)
    }

    fn sign(&self, message: &[u8]) -> Result<Signature, Error> {
        self.state.private_key.sign(message)
    }

    fn encrypt(
        &self,
        other: &PublicKey,
        plaintext: &str,
        algo: ContentEncryptionAlgorithm,
    ) -> Result<String, Error> {
        self.state.private_key.encrypt(other, plaintext, algo)
    }

    fn decrypt_nip44(&self, other: &PublicKey, ciphertext: &str) -> Result<String, Error> {
        self.state.private_key.decrypt_nip44(other, ciphertext)
    }

    fn decrypt_nip04(&self, other: &PublicKey, ciphertext: &str) -> Result<Vec<u8>, Error> {
        self.state.private_key.decrypt_nip04(other, ciphertext)
    }
}
