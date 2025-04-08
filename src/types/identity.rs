use crate::{
    ContentEncryptionAlgorithm, DelegationConditions, EncryptedPrivateKey, Error, Event, EventV1,
    EventV2, Id, KeySecurity, KeySigner, Metadata, PreEvent, PrivateKey, PublicKey, Rumor, RumorV1,
    RumorV2, Signature, Signer,
};
use std::ops::DerefMut;
use std::sync::mpsc::Sender;

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

    /// New `Identity` from an encrypted private key and its password
    pub fn from_encrypted_private_key(epk: EncryptedPrivateKey, pass: &str) -> Result<Self, Error> {
        let key_signer = KeySigner::from_encrypted_private_key(epk, pass)?;
        Ok(Self::Signer(Box::new(key_signer)))
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
    pub async fn sign_id(&self, id: Id) -> Result<Signature, Error> {
        match self {
            Identity::None => Err(Error::NoPublicKey),
            Identity::Public(_) => Err(Error::NoPrivateKey),
            Identity::Signer(boxed_signer) => boxed_signer.sign_id(id).await,
        }
    }

    /// Sign a message (this hashes with SHA-256 first internally)
    pub async fn sign(&self, message: &[u8]) -> Result<Signature, Error> {
        match self {
            Identity::None => Err(Error::NoPublicKey),
            Identity::Public(_) => Err(Error::NoPrivateKey),
            Identity::Signer(boxed_signer) => boxed_signer.sign(message).await,
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

    /// Decrypt
    pub fn decrypt(&self, other: &PublicKey, ciphertext: &str) -> Result<String, Error> {
        match self {
            Identity::None => Err(Error::NoPublicKey),
            Identity::Public(_) => Err(Error::NoPrivateKey),
            Identity::Signer(boxed_signer) => boxed_signer.decrypt(other, ciphertext),
        }
    }

    /// Get NIP-44 conversation key
    pub fn nip44_conversation_key(&self, other: &PublicKey) -> Result<[u8; 32], Error> {
        match self {
            Identity::None => Err(Error::NoPublicKey),
            Identity::Public(_) => Err(Error::NoPrivateKey),
            Identity::Signer(boxed_signer) => boxed_signer.nip44_conversation_key(other),
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

    /// Upgrade the encrypted private key to the latest format
    pub fn upgrade(&mut self, pass: &str, log_n: u8) -> Result<(), Error> {
        match self {
            Identity::None => Err(Error::NoPublicKey),
            Identity::Public(_) => Err(Error::NoPrivateKey),
            Identity::Signer(boxed_signer) => boxed_signer.upgrade(pass, log_n),
        }
    }

    /// Create an event that sets Metadata
    pub async fn create_metadata_event(
        &self,
        input: PreEvent,
        metadata: Metadata,
    ) -> Result<Event, Error> {
        match self {
            Identity::None => Err(Error::NoPublicKey),
            Identity::Public(_) => Err(Error::NoPrivateKey),
            Identity::Signer(boxed_signer) => {
                boxed_signer.create_metadata_event(input, metadata).await
            }
        }
    }

    /// Create a ZapRequest event These events are not published to nostr, they are sent to a lnurl.
    pub async fn create_zap_request_event(
        &self,
        recipient_pubkey: PublicKey,
        zapped_event: Option<Id>,
        millisatoshis: u64,
        relays: Vec<String>,
        content: String,
    ) -> Result<Event, Error> {
        match self {
            Identity::None => Err(Error::NoPublicKey),
            Identity::Public(_) => Err(Error::NoPrivateKey),
            Identity::Signer(boxed_signer) => {
                boxed_signer
                    .create_zap_request_event(
                        recipient_pubkey,
                        zapped_event,
                        millisatoshis,
                        relays,
                        content,
                    )
                    .await
            }
        }
    }

    /// Decrypt the contents of an event
    pub fn decrypt_event_contents(&self, event: &Event) -> Result<String, Error> {
        match self {
            Identity::None => Err(Error::NoPublicKey),
            Identity::Public(_) => Err(Error::NoPrivateKey),
            Identity::Signer(boxed_signer) => boxed_signer.decrypt_event_contents(event),
        }
    }

    /// If a gift wrap event, unwrap and return the inner Rumor
    pub fn unwrap_giftwrap(&self, event: &Event) -> Result<Rumor, Error> {
        match self {
            Identity::None => Err(Error::NoPublicKey),
            Identity::Public(_) => Err(Error::NoPrivateKey),
            Identity::Signer(boxed_signer) => boxed_signer.unwrap_giftwrap(event),
        }
    }

    /// If a gift wrap event, unwrap and return the inner Rumor
    /// @deprecated for migrations only
    pub fn unwrap_giftwrap1(&self, event: &EventV1) -> Result<RumorV1, Error> {
        match self {
            Identity::None => Err(Error::NoPublicKey),
            Identity::Public(_) => Err(Error::NoPrivateKey),
            Identity::Signer(boxed_signer) => boxed_signer.unwrap_giftwrap1(event),
        }
    }

    /// If a gift wrap event, unwrap and return the inner Rumor
    /// @deprecated for migrations only
    pub fn unwrap_giftwrap2(&self, event: &EventV2) -> Result<RumorV2, Error> {
        match self {
            Identity::None => Err(Error::NoPublicKey),
            Identity::Public(_) => Err(Error::NoPrivateKey),
            Identity::Signer(boxed_signer) => boxed_signer.unwrap_giftwrap2(event),
        }
    }

    /// Generate delegation signature
    pub async fn generate_delegation_signature(
        &self,
        delegated_pubkey: PublicKey,
        delegation_conditions: &DelegationConditions,
    ) -> Result<Signature, Error> {
        match self {
            Identity::None => Err(Error::NoPublicKey),
            Identity::Public(_) => Err(Error::NoPrivateKey),
            Identity::Signer(boxed_signer) => {
                boxed_signer
                    .generate_delegation_signature(delegated_pubkey, delegation_conditions)
                    .await
            }
        }
    }

    /// Giftwrap an event
    pub async fn giftwrap(&self, input: PreEvent, pubkey: PublicKey) -> Result<Event, Error> {
        match self {
            Identity::None => Err(Error::NoPublicKey),
            Identity::Public(_) => Err(Error::NoPrivateKey),
            Identity::Signer(boxed_signer) => boxed_signer.giftwrap(input, pubkey).await,
        }
    }

    /// Sign an event
    pub async fn sign_event(&self, input: PreEvent) -> Result<Event, Error> {
        match self {
            Identity::None => Err(Error::NoPublicKey),
            Identity::Public(_) => Err(Error::NoPrivateKey),
            Identity::Signer(boxed_signer) => boxed_signer.sign_event(input).await,
        }
    }

    /// Sign an event with Proof-of-Work
    pub async fn sign_event_with_pow(
        &self,
        input: PreEvent,
        zero_bits: u8,
        work_sender: Option<Sender<u8>>,
    ) -> Result<Event, Error> {
        match self {
            Identity::None => Err(Error::NoPublicKey),
            Identity::Public(_) => Err(Error::NoPrivateKey),
            Identity::Signer(boxed_signer) => {
                boxed_signer
                    .sign_event_with_pow(input, zero_bits, work_sender)
                    .await
            }
        }
    }

    /// Verify delegation signature
    pub fn verify_delegation_signature(
        &self,
        delegated_pubkey: PublicKey,
        delegation_conditions: &DelegationConditions,
        signature: &Signature,
    ) -> Result<(), Error> {
        match self {
            Identity::None => Err(Error::NoPublicKey),
            Identity::Public(_) => Err(Error::NoPrivateKey),
            Identity::Signer(boxed_signer) => boxed_signer.verify_delegation_signature(
                delegated_pubkey,
                delegation_conditions,
                signature,
            ),
        }
    }
}
