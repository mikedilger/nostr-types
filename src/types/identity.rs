use crate::{
    ContentEncryptionAlgorithm, DelegationConditions, EncryptedPrivateKey, Error, Event, EventV1,
    EventV2, FullSigner, Id, KeySecurity, KeySigner, LockableSigner, Metadata, PreEvent,
    PrivateKey, PublicKey, Rumor, RumorV1, RumorV2, Signature,
};
use std::sync::mpsc::Sender;
use std::sync::Arc;

/// All states that your identity can be in
#[derive(Debug, Default)]
pub enum Identity {
    /// No identity information
    #[default]
    None,

    /// Public key only
    Public(PublicKey),

    /// Lockable signer
    LockableSigner(Arc<dyn LockableSigner>),

    /// Full signer (exportable too)
    FullSigner(Arc<dyn FullSigner>),
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
        Ok(Self::FullSigner(Arc::new(key_signer)))
    }

    /// New `Identity` from an encrypted private key and a public key
    pub fn from_locked_parts(pk: PublicKey, epk: EncryptedPrivateKey) -> Self {
        let key_signer = KeySigner::from_locked_parts(epk, pk);
        Self::FullSigner(Arc::new(key_signer))
    }

    /// New `Identity` from an encrypted private key and its password
    pub fn from_encrypted_private_key(epk: EncryptedPrivateKey, pass: &str) -> Result<Self, Error> {
        let key_signer = KeySigner::from_encrypted_private_key(epk, pass)?;
        Ok(Self::FullSigner(Arc::new(key_signer)))
    }

    /// Generate a new `Identity`
    pub fn generate(password: &str, log_n: u8) -> Result<Self, Error> {
        let key_signer = KeySigner::generate(password, log_n)?;
        Ok(Self::FullSigner(Arc::new(key_signer)))
    }

    /// Get access to the inner `LockableSigner`
    pub fn inner_lockable(&self) -> Option<Arc<dyn LockableSigner>> {
        match self {
            Self::None => None,
            Self::Public(_) => None,
            Self::LockableSigner(b) => Some(b.clone()),
            Self::FullSigner(b) => Some(b.clone()),
        }
    }

    /// Get access to the inner `FullSigner`
    pub fn inner_full(&self) -> Option<Arc<dyn FullSigner>> {
        match self {
            Self::None => None,
            Self::Public(_) => None,
            Self::LockableSigner(_) => None,
            Self::FullSigner(b) => Some(b.clone()),
        }
    }

    /// Unlock
    pub fn unlock(&self, password: &str) -> Result<(), Error> {
        if let Self::LockableSigner(arcsigner) = self {
            arcsigner.unlock(password)
        } else if let Self::FullSigner(arcsigner) = self {
            arcsigner.unlock(password)
        } else {
            Ok(())
        }
    }

    /// Lock access to the private key
    pub fn lock(&self) {
        if let Self::LockableSigner(arcsigner) = self {
            arcsigner.lock()
        } else if let Self::FullSigner(arcsigner) = self {
            arcsigner.lock()
        }
    }

    /// Has a public key
    pub fn has_public_key(&self) -> bool {
        !matches!(self, Self::None)
    }

    /// Has a private key
    pub fn has_private_key(&self) -> bool {
        matches!(self, Self::LockableSigner(_)) || matches!(self, Self::FullSigner(_))
    }

    /// Is the identity locked?
    pub fn is_locked(&self) -> bool {
        !self.is_unlocked()
    }

    /// Is the identity unlocked?
    pub fn is_unlocked(&self) -> bool {
        if let Self::LockableSigner(box_signer) = self {
            !box_signer.is_locked()
        } else if let Self::FullSigner(box_signer) = self {
            !box_signer.is_locked()
        } else {
            false
        }
    }

    /// Change the passphrase used for locking access to the private key
    pub fn change_passphrase(&self, old: &str, new: &str, log_n: u8) -> Result<(), Error> {
        match self {
            Self::None => Err(Error::NoPublicKey),
            Self::Public(_) => Err(Error::NoPrivateKey),
            Self::LockableSigner(arcsigner) => arcsigner.change_passphrase(old, new, log_n),
            Self::FullSigner(arcsigner) => arcsigner.change_passphrase(old, new, log_n),
        }
    }

    /// What is the public key?
    pub fn public_key(&self) -> Option<PublicKey> {
        match self {
            Self::None => None,
            Self::Public(pk) => Some(*pk),
            Self::LockableSigner(arcsigner) => Some(arcsigner.public_key()),
            Self::FullSigner(arcsigner) => Some(arcsigner.public_key()),
        }
    }

    /// What is the signer's encrypted private key?
    pub fn encrypted_private_key(&self) -> Option<EncryptedPrivateKey> {
        if let Self::LockableSigner(arcsigner) = self {
            arcsigner.encrypted_private_key()
        } else if let Self::FullSigner(arcsigner) = self {
            arcsigner.encrypted_private_key()
        } else {
            None
        }
    }

    /// Sign a 32-bit hash
    pub async fn sign_id(&self, id: Id) -> Result<Signature, Error> {
        match self {
            Self::None => Err(Error::NoPublicKey),
            Self::Public(_) => Err(Error::NoPrivateKey),
            Self::LockableSigner(arcsigner) => arcsigner.sign_id(id).await,
            Self::FullSigner(arcsigner) => arcsigner.sign_id(id).await,
        }
    }

    /// Sign a message (this hashes with SHA-256 first internally)
    pub async fn sign(&self, message: &[u8]) -> Result<Signature, Error> {
        match self {
            Self::None => Err(Error::NoPublicKey),
            Self::Public(_) => Err(Error::NoPrivateKey),
            Self::LockableSigner(arcsigner) => arcsigner.sign(message).await,
            Self::FullSigner(arcsigner) => arcsigner.sign(message).await,
        }
    }

    /// Encrypt
    pub async fn encrypt(
        &self,
        other: &PublicKey,
        plaintext: &str,
        algo: ContentEncryptionAlgorithm,
    ) -> Result<String, Error> {
        match self {
            Self::None => Err(Error::NoPublicKey),
            Self::Public(_) => Err(Error::NoPrivateKey),
            Self::LockableSigner(arcsigner) => arcsigner.encrypt(other, plaintext, algo).await,
            Self::FullSigner(arcsigner) => arcsigner.encrypt(other, plaintext, algo).await,
        }
    }

    /// Decrypt
    pub async fn decrypt(&self, other: &PublicKey, ciphertext: &str) -> Result<String, Error> {
        match self {
            Self::None => Err(Error::NoPublicKey),
            Self::Public(_) => Err(Error::NoPrivateKey),
            Self::LockableSigner(arcsigner) => arcsigner.decrypt(other, ciphertext).await,
            Self::FullSigner(arcsigner) => arcsigner.decrypt(other, ciphertext).await,
        }
    }

    /// Get NIP-44 conversation key
    pub async fn nip44_conversation_key(&self, other: &PublicKey) -> Result<[u8; 32], Error> {
        match self {
            Self::None => Err(Error::NoPublicKey),
            Self::Public(_) => Err(Error::NoPrivateKey),
            Self::LockableSigner(arcsigner) => arcsigner.nip44_conversation_key(other).await,
            Self::FullSigner(arcsigner) => arcsigner.nip44_conversation_key(other).await,
        }
    }

    /// Get the security level of the private key
    pub fn key_security(&self) -> Result<KeySecurity, Error> {
        match self {
            Self::None => Err(Error::NoPublicKey),
            Self::Public(_) => Err(Error::NoPrivateKey),
            Self::LockableSigner(arcsigner) => arcsigner.key_security(),
            Self::FullSigner(arcsigner) => arcsigner.key_security(),
        }
    }

    /// Upgrade the encrypted private key to the latest format
    pub fn upgrade(&self, pass: &str, log_n: u8) -> Result<(), Error> {
        match self {
            Self::None => Err(Error::NoPublicKey),
            Self::Public(_) => Err(Error::NoPrivateKey),
            Self::LockableSigner(arcsigner) => arcsigner.upgrade(pass, log_n),
            Self::FullSigner(arcsigner) => arcsigner.upgrade(pass, log_n),
        }
    }

    /// Create an event that sets Metadata
    pub async fn create_metadata_event(
        &self,
        input: PreEvent,
        metadata: Metadata,
    ) -> Result<Event, Error> {
        match self {
            Self::None => Err(Error::NoPublicKey),
            Self::Public(_) => Err(Error::NoPrivateKey),
            Self::LockableSigner(arcsigner) => {
                arcsigner.create_metadata_event(input, metadata).await
            }
            Self::FullSigner(arcsigner) => arcsigner.create_metadata_event(input, metadata).await,
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
            Self::None => Err(Error::NoPublicKey),
            Self::Public(_) => Err(Error::NoPrivateKey),
            Self::LockableSigner(arcsigner) => {
                arcsigner
                    .create_zap_request_event(
                        recipient_pubkey,
                        zapped_event,
                        millisatoshis,
                        relays,
                        content,
                    )
                    .await
            }
            Self::FullSigner(arcsigner) => {
                arcsigner
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
    pub async fn decrypt_event_contents(&self, event: &Event) -> Result<String, Error> {
        match self {
            Self::None => Err(Error::NoPublicKey),
            Self::Public(_) => Err(Error::NoPrivateKey),
            Self::LockableSigner(arcsigner) => arcsigner.decrypt_event_contents(event).await,
            Self::FullSigner(arcsigner) => arcsigner.decrypt_event_contents(event).await,
        }
    }

    /// If a gift wrap event, unwrap and return the inner Rumor
    pub async fn unwrap_giftwrap(&self, event: &Event) -> Result<Rumor, Error> {
        match self {
            Self::None => Err(Error::NoPublicKey),
            Self::Public(_) => Err(Error::NoPrivateKey),
            Self::LockableSigner(arcsigner) => arcsigner.unwrap_giftwrap(event).await,
            Self::FullSigner(arcsigner) => arcsigner.unwrap_giftwrap(event).await,
        }
    }

    /// If a gift wrap event, unwrap and return the inner Rumor
    /// @deprecated for migrations only
    pub async fn unwrap_giftwrap1(&self, event: &EventV1) -> Result<RumorV1, Error> {
        match self {
            Self::None => Err(Error::NoPublicKey),
            Self::Public(_) => Err(Error::NoPrivateKey),
            Self::LockableSigner(arcsigner) => arcsigner.unwrap_giftwrap1(event).await,
            Self::FullSigner(arcsigner) => arcsigner.unwrap_giftwrap1(event).await,
        }
    }

    /// If a gift wrap event, unwrap and return the inner Rumor
    /// @deprecated for migrations only
    pub async fn unwrap_giftwrap2(&self, event: &EventV2) -> Result<RumorV2, Error> {
        match self {
            Self::None => Err(Error::NoPublicKey),
            Self::Public(_) => Err(Error::NoPrivateKey),
            Self::LockableSigner(arcsigner) => arcsigner.unwrap_giftwrap2(event).await,
            Self::FullSigner(arcsigner) => arcsigner.unwrap_giftwrap2(event).await,
        }
    }

    /// Generate delegation signature
    pub async fn generate_delegation_signature(
        &self,
        delegated_pubkey: PublicKey,
        delegation_conditions: &DelegationConditions,
    ) -> Result<Signature, Error> {
        match self {
            Self::None => Err(Error::NoPublicKey),
            Self::Public(_) => Err(Error::NoPrivateKey),
            Self::LockableSigner(arcsigner) => {
                arcsigner
                    .generate_delegation_signature(delegated_pubkey, delegation_conditions)
                    .await
            }
            Self::FullSigner(arcsigner) => {
                arcsigner
                    .generate_delegation_signature(delegated_pubkey, delegation_conditions)
                    .await
            }
        }
    }

    /// Giftwrap an event
    pub async fn giftwrap(&self, input: PreEvent, pubkey: PublicKey) -> Result<Event, Error> {
        match self {
            Self::None => Err(Error::NoPublicKey),
            Self::Public(_) => Err(Error::NoPrivateKey),
            Self::LockableSigner(arcsigner) => arcsigner.giftwrap(input, pubkey).await,
            Self::FullSigner(arcsigner) => arcsigner.giftwrap(input, pubkey).await,
        }
    }

    /// Sign an event
    pub async fn sign_event(&self, input: PreEvent) -> Result<Event, Error> {
        match self {
            Self::None => Err(Error::NoPublicKey),
            Self::Public(_) => Err(Error::NoPrivateKey),
            Self::LockableSigner(arcsigner) => arcsigner.sign_event(input).await,
            Self::FullSigner(arcsigner) => arcsigner.sign_event(input).await,
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
            Self::None => Err(Error::NoPublicKey),
            Self::Public(_) => Err(Error::NoPrivateKey),
            Self::LockableSigner(arcsigner) => {
                arcsigner
                    .sign_event_with_pow(input, zero_bits, work_sender)
                    .await
            }
            Self::FullSigner(arcsigner) => {
                arcsigner
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
            Self::None => Err(Error::NoPublicKey),
            Self::Public(_) => Err(Error::NoPrivateKey),
            Self::LockableSigner(arcsigner) => arcsigner.verify_delegation_signature(
                delegated_pubkey,
                delegation_conditions,
                signature,
            ),
            Self::FullSigner(arcsigner) => arcsigner.verify_delegation_signature(
                delegated_pubkey,
                delegation_conditions,
                signature,
            ),
        }
    }
}
