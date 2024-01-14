use crate::{
    ContentEncryptionAlgorithm, EncryptedPrivateKey, Error, Id, KeySecurity, KeySigner, PrivateKey,
    PublicKey, Signature, Signer,
};
use std::ops::DerefMut;

/// All states that your identity can be in
#[derive(Debug, Default)]
pub enum Identity {
    /// No identity information
    #[default]
    None,

    /// Public key only
    Public(PublicKey),

    /// Signer (locked or unlocked)
    Signer(Box<dyn Signer>),
}


// No one besides the Identity has the internal Signer, so we can safely Send
unsafe impl Send for Identity {}

// Nobody can write while someone else is reading with just a non-mutable &reference
unsafe impl Sync for Identity {}

impl Identity {
    /// New `Identity` from a public key
    pub fn from_public_key(pk: PublicKey) -> Self {
        Self::Public(pk)
    }

    /// New `Identity` from a private key
    pub fn from_private_key(pk: PrivateKey, pass: &str, log_n: u8) -> Result<Self, Error> {
        let key_signer = KeySigner::from_private_key(pk, pass, log_n)?;
        Ok(Self::Signer(Box::new(key_signer)))
    }

    /// New `Identity` from an encrypted private key and a public key
    pub fn from_locked_parts(pk: PublicKey, epk: EncryptedPrivateKey) -> Self {
        let key_signer = KeySigner::from_locked_parts(epk, pk);
        Self::Signer(Box::new(key_signer))
    }

    /// Generate a new `Identity`
    pub fn generate(password: &str, log_n: u8) -> Result<Self, Error> {
        let key_signer = KeySigner::generate(password, log_n)?;
        Ok(Self::Signer(Box::new(key_signer)))
    }

    /// Unlock
    pub fn unlock(&mut self, password: &str) -> Result<(), Error> {
        if let Identity::Signer(ref mut boxed_signer) = self {
            boxed_signer.deref_mut().unlock(password)
        } else {
            Ok(())
        }
    }

    /// Lock access to the private key
    pub fn lock(&mut self) {
        if let Identity::Signer(ref mut boxed_signer) = self {
            boxed_signer.deref_mut().lock()
        }
    }

    /// Has a public key
    pub fn has_public_key(&self) -> bool {
        !matches!(self, Identity::None)
    }

    /// Has a private key
    pub fn has_private_key(&self) -> bool {
        matches!(self, Identity::Signer(_))
    }

    /// Is the identity locked?
    pub fn is_locked(&self) -> bool {
        !self.is_unlocked()
    }

    /// Is the identity unlocked?
    pub fn is_unlocked(&self) -> bool {
        if let Identity::Signer(box_signer) = self {
            !box_signer.is_locked()
        } else {
            false
        }
    }

    /// Change the passphrase used for locking access to the private key
    pub fn change_passphrase(&mut self, old: &str, new: &str, log_n: u8) -> Result<(), Error> {
        match self {
            Identity::None => Err(Error::NoPublicKey),
            Identity::Public(_) => Err(Error::NoPrivateKey),
            Identity::Signer(boxed_signer) => boxed_signer.change_passphrase(old, new, log_n),
        }
    }

    /// What is the public key?
    pub fn public_key(&self) -> Option<PublicKey> {
        match self {
            Identity::None => None,
            Identity::Public(pk) => Some(*pk),
            Identity::Signer(boxed_signer) => Some(boxed_signer.public_key()),
        }
    }

    /// What is the signer's encrypted private key?
    pub fn encrypted_private_key(&self) -> Option<&EncryptedPrivateKey> {
        if let Identity::Signer(boxed_signer) = self {
            boxed_signer.encrypted_private_key()
        } else {
            None
        }
    }

    /// Sign a 32-bit hash
    pub fn sign_id(&self, id: Id) -> Result<Signature, Error> {
        match self {
            Identity::None => Err(Error::NoPublicKey),
            Identity::Public(_) => Err(Error::NoPrivateKey),
            Identity::Signer(boxed_signer) => boxed_signer.sign_id(id),
        }
    }

    /// Sign a message (this hashes with SHA-256 first internally)
    pub fn sign(&self, message: &[u8]) -> Result<Signature, Error> {
        match self {
            Identity::None => Err(Error::NoPublicKey),
            Identity::Public(_) => Err(Error::NoPrivateKey),
            Identity::Signer(boxed_signer) => boxed_signer.sign(message),
        }
    }

    /// Encrypt
    pub fn encrypt(
        &self,
        other: &PublicKey,
        plaintext: &str,
        algo: ContentEncryptionAlgorithm,
    ) -> Result<String, Error> {
        match self {
            Identity::None => Err(Error::NoPublicKey),
            Identity::Public(_) => Err(Error::NoPrivateKey),
            Identity::Signer(boxed_signer) => boxed_signer.encrypt(other, plaintext, algo),
        }
    }

    /// Decrypt NIP-44
    pub fn decrypt_nip44(&self, other: &PublicKey, ciphertext: &str) -> Result<String, Error> {
        match self {
            Identity::None => Err(Error::NoPublicKey),
            Identity::Public(_) => Err(Error::NoPrivateKey),
            Identity::Signer(boxed_signer) => boxed_signer.decrypt_nip44(other, ciphertext),
        }
    }

    /// Decrypt NIP-04
    pub fn decrypt_nip04(&self, other: &PublicKey, ciphertext: &str) -> Result<Vec<u8>, Error> {
        match self {
            Identity::None => Err(Error::NoPublicKey),
            Identity::Public(_) => Err(Error::NoPrivateKey),
            Identity::Signer(boxed_signer) => boxed_signer.decrypt_nip04(other, ciphertext),
        }
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
        match self {
            Identity::None => Err(Error::NoPublicKey),
            Identity::Public(_) => Err(Error::NoPrivateKey),
            Identity::Signer(boxed_signer) => boxed_signer.export_private_key_in_hex(pass, log_n),
        }
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
        match self {
            Identity::None => Err(Error::NoPublicKey),
            Identity::Public(_) => Err(Error::NoPrivateKey),
            Identity::Signer(boxed_signer) => {
                boxed_signer.export_private_key_in_bech32(pass, log_n)
            }
        }
    }

    /// Get the security level of the private key
    pub fn key_security(&self) -> Result<KeySecurity, Error> {
        match self {
            Identity::None => Err(Error::NoPublicKey),
            Identity::Public(_) => Err(Error::NoPrivateKey),
            Identity::Signer(boxed_signer) => boxed_signer.key_security(),
        }
    }
}
