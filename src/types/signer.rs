use crate::{
    ContentEncryptionAlgorithm, DelegationConditions, EncryptedPrivateKey, Error, Event, EventKind,
    EventV1, EventV2, Id, KeySecurity, KeySigner, Metadata, PreEvent, PreEventV2, PrivateKey,
    PublicKey, PublicKeyHex, Rumor, RumorV1, RumorV2, Signature, Tag, TagV1, TagV2, Unixtime,
};
use rand::Rng;
use rand_core::OsRng;
use std::fmt;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};
use std::sync::mpsc::Sender;
use std::sync::Arc;
use std::thread;
use std::thread::JoinHandle;

/// Signer operations
pub trait Signer: fmt::Debug {
    /// Is the signer locked?
    fn is_locked(&self) -> bool;

    /// Try to unlock access to the private key
    fn unlock(&mut self, password: &str) -> Result<(), Error>;

    /// Lock access to the private key
    fn lock(&mut self);

    /// Change the passphrase used for locking access to the private key
    fn change_passphrase(&mut self, old: &str, new: &str, log_n: u8) -> Result<(), Error>;

    /// Upgrade the encrypted private key to the latest format
    fn upgrade(&mut self, pass: &str, log_n: u8) -> Result<(), Error>;

    /// What is the signer's public key?
    fn public_key(&self) -> PublicKey;

    /// What is the signer's encrypted private key?
    fn encrypted_private_key(&self) -> Option<&EncryptedPrivateKey>;

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
    fn decrypt(&self, other: &PublicKey, ciphertext: &str) -> Result<String, Error>;

    /// Get NIP-44 conversation key
    fn nip44_conversation_key(&self, other: &PublicKey) -> Result<[u8; 32], Error>;

    /// Export the private key in hex.
    ///
    /// This returns a boolean indicating if the key security was downgraded. If it was,
    /// the caller should save the new self.encrypted_private_key()
    ///
    /// We need the password and log_n parameters to possibly rebuild
    /// the EncryptedPrivateKey when downgrading key security
    fn export_private_key_in_hex(&mut self, pass: &str, log_n: u8)
        -> Result<(String, bool), Error>;

    /// Export the private key in bech32.
    ///
    /// This returns a boolean indicating if the key security was downgraded. If it was,
    /// the caller should save the new self.encrypted_private_key()
    ///
    /// We need the password and log_n parameters to possibly rebuild
    /// the EncryptedPrivateKey when downgrading key security
    fn export_private_key_in_bech32(
        &mut self,
        pass: &str,
        log_n: u8,
    ) -> Result<(String, bool), Error>;

    /// Get the security level of the private key
    fn key_security(&self) -> Result<KeySecurity, Error>;

    /// Generate delegation signature
    fn generate_delegation_signature(
        &self,
        delegated_pubkey: PublicKey,
        delegation_conditions: &DelegationConditions,
    ) -> Result<Signature, Error> {
        let input = format!(
            "nostr:delegation:{}:{}",
            delegated_pubkey.as_hex_string(),
            delegation_conditions.as_string()
        );

        self.sign(input.as_bytes())
    }

    /// Verify delegation signature
    fn verify_delegation_signature(
        &self,
        delegated_pubkey: PublicKey,
        delegation_conditions: &DelegationConditions,
        signature: &Signature,
    ) -> Result<(), Error> {
        let input = format!(
            "nostr:delegation:{}:{}",
            delegated_pubkey.as_hex_string(),
            delegation_conditions.as_string()
        );

        self.public_key().verify(input.as_bytes(), signature)
    }

    /// Sign an event
    fn sign_event(&self, input: PreEvent) -> Result<Event, Error> {
        // Verify the pubkey matches
        if input.pubkey != self.public_key() {
            return Err(Error::InvalidPrivateKey);
        }

        // Generate Id
        let id = input.hash()?;

        // Generate Signature
        let signature = self.sign_id(id)?;

        Ok(Event {
            id,
            pubkey: input.pubkey,
            created_at: input.created_at,
            kind: input.kind,
            tags: input.tags,
            content: input.content,
            sig: signature,
        })
    }

    /// Sign an event
    fn sign_event2(&self, input: PreEventV2) -> Result<EventV2, Error> {
        // Verify the pubkey matches
        if input.pubkey != self.public_key() {
            return Err(Error::InvalidPrivateKey);
        }

        // Generate Id
        let id = input.hash()?;

        // Generate Signature
        let signature = self.sign_id(id)?;

        Ok(EventV2 {
            id,
            pubkey: input.pubkey,
            created_at: input.created_at,
            kind: input.kind,
            tags: input.tags,
            content: input.content,
            sig: signature,
        })
    }

    /// Sign an event with Proof-of-Work
    fn sign_event_with_pow(
        &self,
        mut input: PreEvent,
        zero_bits: u8,
        work_sender: Option<Sender<u8>>,
    ) -> Result<Event, Error> {
        let target = format!("{zero_bits}");

        // Verify the pubkey matches
        if input.pubkey != self.public_key() {
            return Err(Error::InvalidPrivateKey);
        }

        // Strip any pre-existing nonce tags
        input.tags.retain(|t| t.tagname() != "nonce");

        // Add nonce tag to the end
        input.tags.push(Tag::new(&["nonce", "0", &target]));
        let index = input.tags.len() - 1;

        let cores = num_cpus::get();

        let quitting = Arc::new(AtomicBool::new(false));
        let nonce = Arc::new(AtomicU64::new(0)); // will store the nonce that works
        let best_work = Arc::new(AtomicU8::new(0));

        let mut join_handles: Vec<JoinHandle<_>> = Vec::with_capacity(cores);

        for core in 0..cores {
            let mut attempt: u64 = core as u64 * (u64::MAX / cores as u64);
            let mut input = input.clone();
            let quitting = quitting.clone();
            let nonce = nonce.clone();
            let best_work = best_work.clone();
            let work_sender = work_sender.clone();
            let join_handle = thread::spawn(move || {
                loop {
                    // Lower the thread priority so other threads aren't starved
                    let _ = thread_priority::set_current_thread_priority(
                        thread_priority::ThreadPriority::Min,
                    );

                    if quitting.load(Ordering::Relaxed) {
                        break;
                    }

                    input.tags[index].set_index(1, format!("{attempt}"));

                    let Id(id) = input.hash().unwrap();

                    let leading_zeroes = crate::get_leading_zero_bits(&id);
                    if leading_zeroes >= zero_bits {
                        nonce.store(attempt, Ordering::Relaxed);
                        quitting.store(true, Ordering::Relaxed);
                        if let Some(sender) = work_sender.clone() {
                            sender.send(leading_zeroes).unwrap();
                        }
                        break;
                    } else if leading_zeroes > best_work.load(Ordering::Relaxed) {
                        best_work.store(leading_zeroes, Ordering::Relaxed);
                        if let Some(sender) = work_sender.clone() {
                            sender.send(leading_zeroes).unwrap();
                        }
                    }

                    attempt += 1;

                    // We don't update created_at, which is a bit tricky to synchronize.
                }
            });
            join_handles.push(join_handle);
        }

        for joinhandle in join_handles {
            let _ = joinhandle.join();
        }

        // We found the nonce. Do it for reals
        input.tags[index].set_index(1, format!("{}", nonce.load(Ordering::Relaxed)));
        let id = input.hash().unwrap();

        // Signature
        let signature = self.sign_id(id)?;

        Ok(Event {
            id,
            pubkey: input.pubkey,
            created_at: input.created_at,
            kind: input.kind,
            tags: input.tags,
            content: input.content,
            sig: signature,
        })
    }

    /// Giftwrap an event
    fn giftwrap(&self, input: PreEvent, pubkey: PublicKey) -> Result<Event, Error> {
        let sender_pubkey = input.pubkey;

        // Verify the pubkey matches
        if sender_pubkey != self.public_key() {
            return Err(Error::InvalidPrivateKey);
        }

        let seal_backdate = Unixtime(
            input.created_at.0
                - OsRng.sample(rand::distributions::Uniform::new(30, 60 * 60 * 24 * 7)),
        );
        let giftwrap_backdate = Unixtime(
            input.created_at.0
                - OsRng.sample(rand::distributions::Uniform::new(30, 60 * 60 * 24 * 7)),
        );

        let seal = {
            let rumor = Rumor::new(input)?;
            let rumor_json = serde_json::to_string(&rumor)?;
            let encrypted_rumor_json =
                self.encrypt(&pubkey, &rumor_json, ContentEncryptionAlgorithm::Nip44v2)?;

            let pre_seal = PreEvent {
                pubkey: sender_pubkey,
                created_at: seal_backdate,
                kind: EventKind::Seal,
                content: encrypted_rumor_json,
                tags: vec![],
            };

            self.sign_event(pre_seal)?
        };

        // Generate a random keypair for the gift wrap
        let random_signer = {
            let random_private_key = PrivateKey::generate();
            KeySigner::from_private_key(random_private_key, "", 1)
        }?;

        let seal_json = serde_json::to_string(&seal)?;
        let encrypted_seal_json =
            random_signer.encrypt(&pubkey, &seal_json, ContentEncryptionAlgorithm::Nip44v2)?;

        let pre_giftwrap = PreEvent {
            pubkey: random_signer.public_key(),
            created_at: giftwrap_backdate,
            kind: EventKind::GiftWrap,
            content: encrypted_seal_json,
            tags: vec![Tag::new_pubkey(pubkey, None, None)],
        };

        random_signer.sign_event(pre_giftwrap)
    }

    /// Giftwrap an event
    fn giftwrap2(&self, input: PreEventV2, pubkey: PublicKey) -> Result<EventV2, Error> {
        let sender_pubkey = input.pubkey;

        // Verify the pubkey matches
        if sender_pubkey != self.public_key() {
            return Err(Error::InvalidPrivateKey);
        }

        let seal_backdate = Unixtime(
            input.created_at.0
                - OsRng.sample(rand::distributions::Uniform::new(30, 60 * 60 * 24 * 7)),
        );
        let giftwrap_backdate = Unixtime(
            input.created_at.0
                - OsRng.sample(rand::distributions::Uniform::new(30, 60 * 60 * 24 * 7)),
        );

        let seal = {
            let rumor = RumorV2::new(input)?;
            let rumor_json = serde_json::to_string(&rumor)?;
            let encrypted_rumor_json =
                self.encrypt(&pubkey, &rumor_json, ContentEncryptionAlgorithm::Nip44v2)?;

            let pre_seal = PreEventV2 {
                pubkey: sender_pubkey,
                created_at: seal_backdate,
                kind: EventKind::Seal,
                content: encrypted_rumor_json,
                tags: vec![],
            };

            self.sign_event2(pre_seal)?
        };

        // Generate a random keypair for the gift wrap
        let random_signer = {
            let random_private_key = PrivateKey::generate();
            KeySigner::from_private_key(random_private_key, "", 1)
        }?;

        let seal_json = serde_json::to_string(&seal)?;
        let encrypted_seal_json =
            random_signer.encrypt(&pubkey, &seal_json, ContentEncryptionAlgorithm::Nip44v2)?;

        let pre_giftwrap = PreEventV2 {
            pubkey: random_signer.public_key(),
            created_at: giftwrap_backdate,
            kind: EventKind::GiftWrap,
            content: encrypted_seal_json,
            tags: vec![TagV2::Pubkey {
                pubkey: pubkey.into(),
                recommended_relay_url: None,
                petname: None,
                trailing: vec![],
            }],
        };

        random_signer.sign_event2(pre_giftwrap)
    }

    /// Create an event that sets Metadata
    fn create_metadata_event(
        &self,
        mut input: PreEvent,
        metadata: Metadata,
    ) -> Result<Event, Error> {
        input.kind = EventKind::Metadata;
        input.content = serde_json::to_string(&metadata)?;
        self.sign_event(input)
    }

    /// Create a ZapRequest event
    /// These events are not published to nostr, they are sent to a lnurl.
    fn create_zap_request_event(
        &self,
        recipient_pubkey: PublicKey,
        zapped_event: Option<Id>,
        millisatoshis: u64,
        relays: Vec<String>,
        content: String,
    ) -> Result<Event, Error> {
        let mut relays_tag = Tag::new(&["relays"]);
        relays_tag.push_values(relays);

        let mut pre_event = PreEvent {
            pubkey: self.public_key(),
            created_at: Unixtime::now().unwrap(),
            kind: EventKind::ZapRequest,
            tags: vec![
                Tag::new_pubkey(recipient_pubkey, None, None),
                relays_tag,
                Tag::new(&["amount", &format!("{millisatoshis}")]),
            ],
            content,
        };

        if let Some(ze) = zapped_event {
            pre_event.tags.push(Tag::new_event(ze, None, None));
        }

        self.sign_event(pre_event)
    }

    /// Decrypt the contents of an event
    fn decrypt_event_contents(&self, event: &Event) -> Result<String, Error> {
        if !event.kind.contents_are_encrypted() {
            return Err(Error::WrongEventKind);
        }

        let pubkey = if event.pubkey == self.public_key() {
            // If you are the author, get the other pubkey from the tags
            event
                .people()
                .iter()
                .filter_map(|(pk, _, _)| if *pk != event.pubkey { Some(*pk) } else { None })
                .nth(0)
                .unwrap_or(event.pubkey) // in case you sent it to yourself.
        } else {
            event.pubkey
        };

        self.decrypt(&pubkey, &event.content)
    }

    /// If a gift wrap event, unwrap and return the inner Rumor
    fn unwrap_giftwrap(&self, event: &Event) -> Result<Rumor, Error> {
        if event.kind != EventKind::GiftWrap {
            return Err(Error::WrongEventKind);
        }

        // Verify you are tagged
        let mut tagged = false;
        for t in event.tags.iter() {
            if let Ok((pubkey, _, _)) = t.parse_pubkey() {
                if pubkey == self.public_key() {
                    tagged = true;
                }
            }
        }
        if !tagged {
            return Err(Error::InvalidRecipient);
        }

        // Decrypt the content
        let content = self.decrypt(&event.pubkey, &event.content)?;

        // Translate into a seal Event
        let seal: Event = serde_json::from_str(&content)?;

        // Verify it is a Seal
        if seal.kind != EventKind::Seal {
            return Err(Error::WrongEventKind);
        }

        // Note the author
        let author = seal.pubkey;

        // Decrypt the content
        let content = self.decrypt(&seal.pubkey, &seal.content)?;

        // Translate into a Rumor
        let rumor: Rumor = serde_json::from_str(&content)?;

        // Compae the author
        if rumor.pubkey != author {
            return Err(Error::InvalidPublicKey);
        }

        // Return the Rumor
        Ok(rumor)
    }

    /// If a gift wrap event, unwrap and return the inner Rumor
    /// @deprecated for migrations only
    fn unwrap_giftwrap2(&self, event: &EventV2) -> Result<RumorV2, Error> {
        if event.kind != EventKind::GiftWrap {
            return Err(Error::WrongEventKind);
        }

        // Verify you are tagged
        let pkhex: PublicKeyHex = self.public_key().into();
        let mut tagged = false;
        for t in event.tags.iter() {
            if let TagV2::Pubkey { pubkey, .. } = t {
                if *pubkey == pkhex {
                    tagged = true;
                }
            }
        }
        if !tagged {
            return Err(Error::InvalidRecipient);
        }

        // Decrypt the content
        let content = self.decrypt(&event.pubkey, &event.content)?;

        // Translate into a seal Event
        let seal: EventV2 = serde_json::from_str(&content)?;

        // Verify it is a Seal
        if seal.kind != EventKind::Seal {
            return Err(Error::WrongEventKind);
        }

        // Note the author
        let author = seal.pubkey;

        // Decrypt the content
        let content = self.decrypt(&seal.pubkey, &seal.content)?;

        // Translate into a Rumor
        let rumor: RumorV2 = serde_json::from_str(&content)?;

        // Compae the author
        if rumor.pubkey != author {
            return Err(Error::InvalidPublicKey);
        }

        // Return the Rumor
        Ok(rumor)
    }

    /// If a gift wrap event, unwrap and return the inner Rumor
    /// @deprecated for migrations only
    fn unwrap_giftwrap1(&self, event: &EventV1) -> Result<RumorV1, Error> {
        if event.kind != EventKind::GiftWrap {
            return Err(Error::WrongEventKind);
        }

        // Verify you are tagged
        let pkhex: PublicKeyHex = self.public_key().into();
        let mut tagged = false;
        for t in event.tags.iter() {
            if let TagV1::Pubkey { pubkey, .. } = t {
                if *pubkey == pkhex {
                    tagged = true;
                }
            }
        }
        if !tagged {
            return Err(Error::InvalidRecipient);
        }

        // Decrypt the content
        let content = self.decrypt(&event.pubkey, &event.content)?;

        // Translate into a seal Event
        let seal: EventV1 = serde_json::from_str(&content)?;

        // Verify it is a Seal
        if seal.kind != EventKind::Seal {
            return Err(Error::WrongEventKind);
        }

        // Note the author
        let author = seal.pubkey;

        // Decrypt the content
        let content = self.decrypt(&seal.pubkey, &seal.content)?;

        // Translate into a Rumor
        let rumor: RumorV1 = serde_json::from_str(&content)?;

        // Compae the author
        if rumor.pubkey != author {
            return Err(Error::InvalidPublicKey);
        }

        // Return the Rumor
        Ok(rumor)
    }
}
