use super::{
    ContentEncryptionAlgorithm, EventDelegation, EventKind, Id, Metadata, MilliSatoshi,
    NostrBech32, NostrUrl, PrivateKey, PublicKey, PublicKeyHex, RelayUrl, Signature, Tag, Unixtime,
};
use crate::Error;
use lightning_invoice::Invoice;
use rand::Rng;
use rand_core::OsRng;
#[cfg(feature = "speedy")]
use regex::Regex;
use serde::{Deserialize, Serialize};
#[cfg(feature = "speedy")]
use speedy::{Readable, Writable};
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};
use std::sync::mpsc::Sender;
use std::sync::Arc;
use std::thread;
use std::thread::JoinHandle;

/// The main event type
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "speedy", derive(Readable, Writable))]
pub struct Event {
    /// The Id of the event, generated as a SHA256 of the inner event data
    pub id: Id,

    /// The public key of the actor who created the event
    pub pubkey: PublicKey,

    /// The (unverified) time at which the event was created
    pub created_at: Unixtime,

    /// The kind of event
    pub kind: EventKind,

    /// The signature of the event, which cryptographically verifies that the holder of
    /// the PrivateKey matching the event's PublicKey generated (or authorized) this event.
    /// The signature is taken over the id field only, but the id field is taken over
    /// the rest of the event data.
    pub sig: Signature,

    /// DEPRECATED (please set to Null): An optional verified time for the event (using OpenTimestamp)
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub ots: Option<String>,

    /// The content of the event
    pub content: String,

    /// A set of tags that apply to the event
    pub tags: Vec<Tag>,
}

macro_rules! serialize_inner_event {
    ($pubkey:expr, $created_at:expr, $kind:expr, $tags:expr,
     $content:expr) => {{
        format!(
            "[0,{},{},{},{},{}]",
            serde_json::to_string($pubkey)?,
            serde_json::to_string($created_at)?,
            serde_json::to_string($kind)?,
            serde_json::to_string($tags)?,
            serde_json::to_string($content)?
        )
    }};
}

/// Data used to construct an event
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "speedy", derive(Readable, Writable))]
pub struct PreEvent {
    /// The public key of the actor who is creating the event
    pub pubkey: PublicKey,
    /// The time at which the event was created
    pub created_at: Unixtime,
    /// The kind of event
    pub kind: EventKind,
    /// A set of tags that apply to the event
    pub tags: Vec<Tag>,
    /// The content of the event
    pub content: String,
}

impl PreEvent {
    /// Generate an ID from this PreEvent for use in an Event or a Rumor
    pub fn hash(&self) -> Result<Id, Error> {
        use secp256k1::hashes::Hash;

        let serialized: String = serialize_inner_event!(
            &self.pubkey,
            &self.created_at,
            &self.kind,
            &self.tags,
            &self.content
        );

        // Hash
        let hash = secp256k1::hashes::sha256::Hash::hash(serialized.as_bytes());
        let id: [u8; 32] = hash.to_byte_array();
        Ok(Id(id))
    }

    /// Create a rumor, wrapped in a seal, shrouded in a giftwrap
    /// The input.pubkey must match the privkey
    /// See NIP-59
    pub fn into_gift_wrap(self, privkey: &PrivateKey, pubkey: &PublicKey) -> Result<Event, Error> {
        let sender_pubkey = self.pubkey;

        if privkey.public_key() != sender_pubkey {
            return Err(Error::InvalidPrivateKey);
        }

        let seal_backdate = Unixtime(
            self.created_at.0
                - OsRng.sample(rand::distributions::Uniform::new(30, 60 * 60 * 24 * 7)),
        );
        let giftwrap_backdate = Unixtime(
            self.created_at.0
                - OsRng.sample(rand::distributions::Uniform::new(30, 60 * 60 * 24 * 7)),
        );

        let seal = {
            let rumor = Rumor::new(self)?;
            let rumor_json = serde_json::to_string(&rumor)?;
            let encrypted_rumor_json =
                privkey.encrypt(pubkey, &rumor_json, ContentEncryptionAlgorithm::Nip44v2)?;

            let pre_seal = PreEvent {
                pubkey: sender_pubkey,
                created_at: seal_backdate,
                kind: EventKind::Seal,
                content: encrypted_rumor_json,
                tags: vec![],
            };

            Event::new(pre_seal, privkey)?
        };

        // Generate a random keypair for the gift wrap
        let random_private_key = PrivateKey::generate();

        let seal_json = serde_json::to_string(&seal)?;
        let encrypted_seal_json =
            random_private_key.encrypt(pubkey, &seal_json, ContentEncryptionAlgorithm::Nip44v2)?;

        let pre_giftwrap = PreEvent {
            pubkey: random_private_key.public_key(),
            created_at: giftwrap_backdate,
            kind: EventKind::GiftWrap,
            content: encrypted_seal_json,
            tags: vec![Tag::Pubkey {
                pubkey: (*pubkey).into(),
                recommended_relay_url: None,
                petname: None,
                trailing: vec![],
            }],
        };

        Event::new(pre_giftwrap, &random_private_key)
    }
}

/// A Rumor is an Event without a signature
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "speedy", derive(Readable, Writable))]
pub struct Rumor {
    /// The Id of the event, generated as a SHA256 of the inner event data
    pub id: Id,

    /// The public key of the actor who created the event
    pub pubkey: PublicKey,

    /// The (unverified) time at which the event was created
    pub created_at: Unixtime,

    /// The kind of event
    pub kind: EventKind,

    /// The content of the event
    pub content: String,

    /// A set of tags that apply to the event
    pub tags: Vec<Tag>,
}

impl Rumor {
    /// Create a new rumor
    pub fn new(input: PreEvent) -> Result<Rumor, Error> {
        // Generate Id
        let id = input.hash()?;

        Ok(Rumor {
            id,
            pubkey: input.pubkey,
            created_at: input.created_at,
            kind: input.kind,
            tags: input.tags,
            content: input.content,
        })
    }

    /// Turn into an Event (the signature will be all zeroes)
    pub fn into_event_with_bad_signature(self) -> Event {
        Event {
            id: self.id,
            pubkey: self.pubkey,
            created_at: self.created_at,
            kind: self.kind,
            sig: Signature::zeroes(),
            ots: None,
            content: self.content,
            tags: self.tags,
        }
    }
}

/// Data about a Zap
#[derive(Clone, Debug, Copy)]
pub struct ZapData {
    /// The event that was zapped
    pub id: Id,

    /// The amount that the event was zapped
    pub amount: MilliSatoshi,

    /// The public key of the person who provided the zap
    pub pubkey: PublicKey,

    /// The public key of the zap provider, for verification purposes
    pub provider_pubkey: PublicKey,
}

impl Event {
    /// Create a new event
    pub fn new(input: PreEvent, privkey: &PrivateKey) -> Result<Event, Error> {
        // Generate Id
        let id = input.hash()?;

        // Generate Signature
        let signature = privkey.sign_id(id)?;

        Ok(Event {
            id,
            pubkey: input.pubkey,
            created_at: input.created_at,
            kind: input.kind,
            tags: input.tags,
            content: input.content,
            ots: None,
            sig: signature,
        })
    }

    /// Create a new event with proof of work.
    ///
    /// This can take a long time, and is only cancellable by killing the thread.
    pub fn new_with_pow(
        mut input: PreEvent,
        privkey: &PrivateKey,
        zero_bits: u8,
        work_sender: Option<Sender<u8>>,
    ) -> Result<Event, Error> {
        let target = Some(format!("{zero_bits}"));

        // Strip any pre-existing nonce tags
        input.tags.retain(|t| !matches!(t, Tag::Nonce { .. }));

        // Add nonce tag to the end
        input.tags.push(Tag::Nonce {
            nonce: "0".to_string(),
            target: target.clone(),
            trailing: Vec::new(),
        });
        let index = input.tags.len() - 1;

        let cores = num_cpus::get();

        let quitting = Arc::new(AtomicBool::new(false));
        let nonce = Arc::new(AtomicU64::new(0)); // will store the nonce that works
        let best_work = Arc::new(AtomicU8::new(0));

        let mut join_handles: Vec<JoinHandle<_>> = Vec::with_capacity(cores);

        for core in 0..cores {
            let mut attempt: u64 = core as u64 * (u64::MAX / cores as u64);
            let mut input = input.clone();
            let target = target.clone();
            let index = index;
            let quitting = quitting.clone();
            let nonce = nonce.clone();
            let zero_bits = zero_bits;
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

                    input.tags[index] = Tag::Nonce {
                        nonce: format!("{attempt}"),
                        target: target.clone(),
                        trailing: Vec::new(),
                    };

                    let Id(id) = input.hash().unwrap();

                    let leading_zeroes = get_leading_zero_bits(&id);
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
        input.tags[index] = Tag::Nonce {
            nonce: format!("{}", nonce.load(Ordering::Relaxed)),
            target,
            trailing: Vec::new(),
        };
        let id = input.hash().unwrap();

        // Signature
        let signature = privkey.sign_id(id)?;

        Ok(Event {
            id,
            pubkey: input.pubkey,
            created_at: input.created_at,
            kind: input.kind,
            tags: input.tags,
            content: input.content,
            ots: None,
            sig: signature,
        })
    }

    /// Check the validity of an event. This is useful if you deserialize an event
    /// from the network. If you create an event using new() it should already be
    /// trustworthy.
    pub fn verify(&self, maxtime: Option<Unixtime>) -> Result<(), Error> {
        use secp256k1::hashes::Hash;

        let serialized: String = serialize_inner_event!(
            &self.pubkey,
            &self.created_at,
            &self.kind,
            &self.tags,
            &self.content
        );

        // Verify the signature
        self.pubkey.verify(serialized.as_bytes(), &self.sig)?;

        // Also verify the ID is the SHA256
        // (the above verify function also does it internally,
        //  so there is room for improvement here)
        let hash = secp256k1::hashes::sha256::Hash::hash(serialized.as_bytes());
        let id: [u8; 32] = hash.to_byte_array();

        // Optional verify that the message was in the past
        if let Some(mt) = maxtime {
            if self.created_at > mt {
                return Err(Error::EventInFuture);
            }
        }

        if id != self.id.0 {
            Err(Error::HashMismatch)
        } else {
            Ok(())
        }
    }

    // Mock data for testing
    #[allow(dead_code)]
    pub(crate) fn mock() -> Event {
        let private_key = PrivateKey::mock();
        let public_key = private_key.public_key();
        let pre = PreEvent {
            pubkey: public_key,
            created_at: Unixtime::mock(),
            kind: EventKind::mock(),
            tags: vec![Tag::mock(), Tag::mock()],
            content: "This is a test".to_string(),
        };
        Event::new(pre, &private_key).unwrap()
    }

    /// Create an event that sets Metadata
    pub fn new_set_metadata(
        mut input: PreEvent,
        privkey: &PrivateKey,
        metadata: Metadata,
    ) -> Result<Event, Error> {
        input.kind = EventKind::Metadata;
        input.content = serde_json::to_string(&metadata)?;
        Event::new(input, privkey)
    }

    /// Create a ZapRequest event
    /// These events are not published to nostr, they are sent to a lnurl.
    pub fn new_zap_request(
        privkey: &PrivateKey,
        recipient_pubkey: PublicKeyHex,
        zapped_event: Option<Id>,
        millisatoshis: u64,
        relays: Vec<String>,
        content: String,
    ) -> Result<Event, Error> {
        let mut pre_event = PreEvent {
            pubkey: privkey.public_key(),
            created_at: Unixtime::now().unwrap(),
            kind: EventKind::ZapRequest,
            tags: vec![
                Tag::Pubkey {
                    pubkey: recipient_pubkey,
                    recommended_relay_url: None,
                    petname: None,
                    trailing: Vec::new(),
                },
                Tag::Other {
                    tag: "relays".to_owned(),
                    data: relays,
                },
                Tag::Other {
                    tag: "amount".to_owned(),
                    data: vec![format!("{millisatoshis}")],
                },
            ],
            content,
        };

        if let Some(ze) = zapped_event {
            pre_event.tags.push(Tag::Event {
                id: ze,
                recommended_relay_url: None,
                marker: None,
                trailing: Vec::new(),
            });
        }

        Event::new(pre_event, privkey)
    }

    /// Get the effective event kind for events which have 'k' tags
    pub fn effective_kind(&self) -> EventKind {
        for tag in self.tags.iter() {
            if let Tag::Kind { kind, .. } = tag {
                return *kind;
            }
        }

        self.kind
    }

    /// If an event is an EncryptedDirectMessage, decrypt it's contents
    pub fn decrypted_contents(&self, private_key: &PrivateKey) -> Result<String, Error> {
        if self.kind != EventKind::EncryptedDirectMessage {
            return Err(Error::WrongEventKind);
        }

        let pubkey = if self.pubkey == private_key.public_key() {
            // If you are the author, get the pubkey from the tags
            self.people()
                .iter()
                .filter_map(|(pkh, _, _)| PublicKey::try_from(pkh).ok())
                .filter(|pk| *pk != self.pubkey)
                .nth(0)
                .unwrap_or(self.pubkey) // in case you sent it to yourself.
        } else {
            self.pubkey
        };

        let decrypted_bytes = private_key.decrypt_nip04(&pubkey, &self.content)?;

        let s: String = String::from_utf8_lossy(&decrypted_bytes).into();
        Ok(s)
    }

    /// If the event refers to people by tag, get all the PublicKeys it refers to
    /// along with recommended relay URL and petname for each
    pub fn people(&self) -> Vec<(PublicKeyHex, Option<RelayUrl>, Option<String>)> {
        let mut output: Vec<(PublicKeyHex, Option<RelayUrl>, Option<String>)> = Vec::new();
        // All 'p' tags
        for tag in self.tags.iter() {
            if let Tag::Pubkey {
                pubkey,
                recommended_relay_url,
                petname,
                ..
            } = tag
            {
                output.push((
                    pubkey.to_owned(),
                    recommended_relay_url
                        .as_ref()
                        .and_then(|rru| RelayUrl::try_from_unchecked_url(rru).ok()),
                    petname.to_owned(),
                ));
            }
        }

        output
    }

    /// If the pubkey is tagged in the event
    pub fn is_tagged(&self, pubkey: &PublicKey) -> bool {
        let pkh: PublicKeyHex = pubkey.into();

        for tag in self.tags.iter() {
            if let Tag::Pubkey { pubkey, .. } = tag {
                if *pubkey == pkh {
                    return true;
                }
            }
        }

        false
    }

    /// If the event refers to people within the contents, get all the PublicKeys it refers
    /// to within the contents.
    pub fn people_referenced_in_content(&self) -> Vec<PublicKey> {
        let mut output = Vec::new();
        for nurl in NostrUrl::find_all_in_string(&self.content).drain(..) {
            if let NostrBech32::Pubkey(pk) = nurl.0 {
                output.push(pk);
            }
            if let NostrBech32::Profile(prof) = nurl.0 {
                output.push(prof.pubkey);
            }
        }
        output
    }

    /// Is the event a reply?
    #[deprecated(since = "0.2.0", note = "please use `replies_to` instead")]
    pub fn is_reply(&self) -> bool {
        if !self.kind.is_feed_displayable() {
            return false;
        }

        for tag in self.tags.iter() {
            if let Tag::Event { .. } = tag {
                return true;
            }
        }

        false
    }

    /// If this event replies to another, get that other event's Id along with
    /// an optional recommended_relay_url
    pub fn replies_to(&self) -> Option<(Id, Option<RelayUrl>)> {
        if !self.kind.is_feed_displayable() {
            return None;
        }

        // Kind=6 'e' tags are always considered mentions, not replies.
        if self.kind == EventKind::Repost {
            return None;
        }

        // look for an 'E' tag (EventParent)
        for tag in self.tags.iter() {
            if let Tag::EventParent {
                id,
                recommended_relay_url,
                ..
            } = tag
            {
                return Some((
                    *id,
                    recommended_relay_url
                        .as_ref()
                        .and_then(|rru| RelayUrl::try_from_unchecked_url(rru).ok()),
                ));
            }
        }

        // If there are no 'e' tags, then none
        let num_e_tags = self
            .tags
            .iter()
            .filter(|e| matches!(e, Tag::Event { .. }))
            .count();
        if num_e_tags == 0 {
            return None;
        }

        // look for an 'e' tag with marker 'reply'
        for tag in self.tags.iter() {
            if let Tag::Event {
                id,
                recommended_relay_url,
                marker,
                ..
            } = tag
            {
                if marker.is_some() && marker.as_deref().unwrap() == "reply" {
                    return Some((
                        *id,
                        recommended_relay_url
                            .as_ref()
                            .and_then(|rru| RelayUrl::try_from_unchecked_url(rru).ok()),
                    ));
                }
            }
        }

        // look for an 'e' tag with marker 'root'
        for tag in self.tags.iter() {
            if let Tag::Event {
                id,
                recommended_relay_url,
                marker,
                ..
            } = tag
            {
                if marker.is_some() && marker.as_deref().unwrap() == "root" {
                    return Some((
                        *id,
                        recommended_relay_url
                            .as_ref()
                            .and_then(|rru| RelayUrl::try_from_unchecked_url(rru).ok()),
                    ));
                }
            }
        }

        // Use the last 'e' tag if unmarked
        if let Some(Tag::Event {
            id,
            recommended_relay_url,
            marker,
            ..
        }) = self
            .tags
            .iter()
            .rev()
            .find(|t| matches!(t, Tag::Event { .. }))
        {
            if marker.is_none() {
                return Some((
                    *id,
                    recommended_relay_url
                        .as_ref()
                        .and_then(|rru| RelayUrl::try_from_unchecked_url(rru).ok()),
                ));
            }
        }

        // Otherwise there are 'e' tags but they have unrecognized markings
        // so we will not consider them as replies.

        None
    }

    /// If this event replies to a thread, get that threads root event Id if
    /// available, along with an optional recommended_relay_url
    pub fn replies_to_root(&self) -> Option<(Id, Option<RelayUrl>)> {
        if !self.kind.is_feed_displayable() {
            return None;
        }

        // look for an 'e' tag with marker 'root'
        for tag in self.tags.iter() {
            if let Tag::Event {
                id,
                recommended_relay_url,
                marker,
                ..
            } = tag
            {
                if marker.is_some() && marker.as_deref().unwrap() == "root" {
                    return Some((
                        *id,
                        recommended_relay_url
                            .as_ref()
                            .and_then(|rru| RelayUrl::try_from_unchecked_url(rru).ok()),
                    ));
                }
            }
        }

        // otherwise use the first 'e' tag if unmarked
        // (even if there is only 1 'e' tag which means it is both root and reply)
        if let Some(Tag::Event {
            id,
            recommended_relay_url,
            marker,
            ..
        }) = self.tags.iter().find(|t| matches!(t, Tag::Event { .. }))
        {
            if marker.is_none() {
                return Some((
                    *id,
                    recommended_relay_url
                        .as_ref()
                        .and_then(|rru| RelayUrl::try_from_unchecked_url(rru).ok()),
                ));
            }
        }

        None
    }

    /// All events IDs that this event refers to, whether root, reply, mention, or otherwise
    /// along with optional recommended relay URLs
    pub fn referred_events(&self) -> Vec<(Id, Option<RelayUrl>, Option<String>)> {
        let mut output: Vec<(Id, Option<RelayUrl>, Option<String>)> = Vec::new();

        // Collect every 'e' tag and 'E' tag
        for tag in self.tags.iter() {
            if let Tag::Event {
                id,
                recommended_relay_url,
                marker,
                ..
            } = tag
            {
                output.push((
                    *id,
                    recommended_relay_url
                        .as_ref()
                        .and_then(|rru| RelayUrl::try_from_unchecked_url(rru).ok()),
                    marker.clone(),
                ));
            } else if let Tag::EventParent {
                id,
                recommended_relay_url,
                ..
            } = tag
            {
                output.push((
                    *id,
                    recommended_relay_url
                        .as_ref()
                        .and_then(|rru| RelayUrl::try_from_unchecked_url(rru).ok()),
                    None,
                ));
            }
        }

        output
    }

    /// If this event mentions others, get those other event Ids
    /// and optional recommended relay Urls
    pub fn mentions(&self) -> Vec<(Id, Option<RelayUrl>)> {
        if !self.kind.is_feed_displayable() {
            return vec![];
        }

        let mut output: Vec<(Id, Option<RelayUrl>)> = Vec::new();

        // For kind=6, all 'e' tags are mentions
        if self.kind == EventKind::Repost {
            for tag in self.tags.iter() {
                if let Tag::Event {
                    id,
                    recommended_relay_url,
                    ..
                } = tag
                {
                    output.push((
                        *id,
                        recommended_relay_url
                            .as_ref()
                            .and_then(|rru| RelayUrl::try_from_unchecked_url(rru).ok()),
                    ));
                }
            }

            return output;
        }

        // Look for nostr links within the content

        // Collect every 'e' tag marked as 'mention'
        for tag in self.tags.iter() {
            if let Tag::Event {
                id,
                recommended_relay_url,
                marker,
                ..
            } = tag
            {
                if marker.is_some() && marker.as_deref().unwrap() == "mention" {
                    output.push((
                        *id,
                        recommended_relay_url
                            .as_ref()
                            .and_then(|rru| RelayUrl::try_from_unchecked_url(rru).ok()),
                    ));
                }
            }
        }

        // Collect every unmarked 'e' tag that is not the first or last
        let e_tags: Vec<&Tag> = self
            .tags
            .iter()
            .filter(|e| matches!(e, Tag::Event { .. }))
            .collect();
        if e_tags.len() > 2 {
            // mentions are everything other than first and last
            for tag in &e_tags[1..e_tags.len() - 1] {
                if let Tag::Event {
                    id,
                    recommended_relay_url,
                    marker,
                    ..
                } = tag
                {
                    if marker.is_none() {
                        output.push((
                            *id,
                            recommended_relay_url
                                .as_ref()
                                .and_then(|rru| RelayUrl::try_from_unchecked_url(rru).ok()),
                        ));
                    }
                }
            }
        }

        output
    }

    /// If this event reacts to another, get that other event's Id,
    /// the reaction content, and an optional Recommended relay Url
    pub fn reacts_to(&self) -> Option<(Id, String, Option<RelayUrl>)> {
        if self.kind != EventKind::Reaction {
            return None;
        }

        // The last 'e' tag is it
        if let Some(Tag::Event {
            id,
            recommended_relay_url,
            ..
        }) = self
            .tags
            .iter()
            .rev()
            .find(|t| matches!(t, Tag::Event { .. }))
        {
            return Some((
                *id,
                self.content.clone(),
                recommended_relay_url
                    .as_ref()
                    .and_then(|rru| RelayUrl::try_from_unchecked_url(rru).ok()),
            ));
        }

        None
    }

    /// If this event deletes others, get all the Ids of the events that it deletes
    /// along with the reason for the deletion
    pub fn deletes(&self) -> Option<(Vec<Id>, String)> {
        if self.kind != EventKind::EventDeletion {
            return None;
        }

        let mut ids: Vec<Id> = Vec::new();

        // All 'e' tags are deleted
        for tag in self.tags.iter() {
            if let Tag::Event { id, .. } = tag {
                ids.push(*id);
            }
        }

        if ids.is_empty() {
            None
        } else {
            Some((ids, self.content.clone()))
        }
    }

    /// If this event zaps another event, get data about that.
    ///
    /// That includes the Id, the amount, and the public key of the provider,
    /// all of which should be verified by the caller.
    ///
    /// Errors returned from this are not fatal, but may be useful for
    /// explaining to a user why a zap receipt is invalid.
    pub fn zaps(&self) -> Result<Option<ZapData>, Error> {
        if self.kind != EventKind::Zap {
            return Ok(None);
        }

        let mut zapped_id: Option<Id> = None;
        let mut zapped_amount: Option<MilliSatoshi> = None;
        let mut zapped_pubkey: Option<PublicKey> = None;

        for tag in self.tags.iter() {
            if let Tag::Other { tag, data } = tag {
                // Find the bolt11 tag
                if tag != "bolt11" {
                    continue;
                }
                if data.is_empty() {
                    return Err(Error::ZapReceipt("missing bolt11 tag value".to_string()));
                }

                // Extract as an Invoice
                let result = Invoice::from_str(&data[0]);
                if let Err(e) = result {
                    return Err(Error::ZapReceipt(format!("bolt11 failed to parse: {}", e)));
                }
                let invoice = result.unwrap();

                // Verify the signature
                if let Err(e) = invoice.check_signature() {
                    return Err(Error::ZapReceipt(format!(
                        "bolt11 signature check failed: {}",
                        e
                    )));
                }

                // Get the public key
                let secpk = match invoice.payee_pub_key() {
                    Some(pubkey) => pubkey.to_owned(),
                    None => invoice.recover_payee_pub_key(),
                };
                let (xonlypk, _) = secpk.x_only_public_key();
                let pubkeybytes = xonlypk.serialize();
                let pubkey = match PublicKey::from_bytes(&pubkeybytes, false) {
                    Ok(pubkey) => pubkey,
                    Err(e) => {
                        return Err(Error::ZapReceipt(format!("payee public key error: {}", e)))
                    }
                };
                zapped_pubkey = Some(pubkey);

                if let Some(u) = invoice.amount_milli_satoshis() {
                    zapped_amount = Some(MilliSatoshi(u));
                } else {
                    return Err(Error::ZapReceipt(
                        "Amount missing from zap receipt".to_string(),
                    ));
                }
            }
            if let Tag::Event { id, .. } = tag {
                zapped_id = Some(*id);
            }
        }

        if zapped_id.is_none() {
            // This probably means a person was zapped, not a note. So not an error.
            return Ok(None);
        }
        if zapped_amount.is_none() {
            return Err(Error::ZapReceipt("Missing amount".to_string()));
        }
        if zapped_pubkey.is_none() {
            return Err(Error::ZapReceipt("Missing payee public key".to_string()));
        }

        Ok(Some(ZapData {
            id: zapped_id.unwrap(),
            amount: zapped_amount.unwrap(),
            pubkey: zapped_pubkey.unwrap(),
            provider_pubkey: self.pubkey,
        }))
    }

    /// If this event specifies the client that created it, return that client string
    pub fn client(&self) -> Option<String> {
        for tag in self.tags.iter() {
            if let Tag::Other { tag, data } = tag {
                if tag == "client" && !data.is_empty() {
                    return Some(data[0].clone());
                }
            }
        }

        None
    }

    /// If this event specifies a subject, return that subject string
    pub fn subject(&self) -> Option<String> {
        for tag in self.tags.iter() {
            if let Tag::Subject { subject, .. } = tag {
                return Some(subject.clone());
            }
        }

        None
    }

    /// If this event specifies a content warning, return that subject string
    pub fn content_warning(&self) -> Option<String> {
        for tag in self.tags.iter() {
            if let Tag::ContentWarning { warning, .. } = tag {
                return Some(warning.clone());
            }
        }

        None
    }

    /// If this is a parameterized event, get the parameter
    pub fn parameter(&self) -> Option<String> {
        if self.kind.is_parameterized_replaceable() {
            for tag in self.tags.iter() {
                if let Tag::Identifier { d, .. } = tag {
                    return Some(d.to_owned());
                }
            }
            Some("".to_owned()) // implicit
        } else {
            None
        }
    }

    /// Return all the hashtags this event refers to
    pub fn hashtags(&self) -> Vec<String> {
        if !self.kind.is_feed_displayable() {
            return vec![];
        }

        let mut output: Vec<String> = Vec::new();

        for tag in self.tags.iter() {
            if let Tag::Hashtag { hashtag, .. } = tag {
                output.push(hashtag.clone());
            }
        }

        output
    }

    /// Return all the URLs this event refers to
    pub fn urls(&self) -> Vec<RelayUrl> {
        if !self.kind.is_feed_displayable() {
            return vec![];
        }

        let mut output: Vec<RelayUrl> = Vec::new();

        for tag in self.tags.iter() {
            if let Tag::Reference { url, .. } = tag {
                if let Ok(relay_url) = RelayUrl::try_from_unchecked_url(url) {
                    output.push(relay_url);
                }
            }
        }

        output
    }

    /// Get the proof-of-work count of leading bits
    pub fn pow(&self) -> u8 {
        // Count leading bits in the Id field
        let zeroes: u8 = get_leading_zero_bits(&self.id.0);

        // Check that they meant it
        let mut target_zeroes: u8 = 0;
        for tag in self.tags.iter() {
            if let Tag::Nonce { target, .. } = tag {
                if let Some(t) = target {
                    target_zeroes = t.parse::<u8>().unwrap_or(0);
                }
                break;
            }
        }

        zeroes.min(target_zeroes)
    }

    /// Was this event delegated, was that valid, and if so what is the pubkey of
    /// the delegator?
    pub fn delegation(&self) -> EventDelegation {
        for tag in self.tags.iter() {
            if let Tag::Delegation {
                pubkey,
                conditions,
                sig,
                ..
            } = tag
            {
                // Convert hex strings into functional types
                let signature = match Signature::try_from_hex_string(sig) {
                    Ok(sig) => sig,
                    Err(e) => return EventDelegation::InvalidDelegation(format!("{e}")),
                };
                let delegator_pubkey = match PublicKey::try_from_hex_string(pubkey, true) {
                    Ok(pk) => pk,
                    Err(e) => return EventDelegation::InvalidDelegation(format!("{e}")),
                };

                // Verify the delegation tag
                match conditions.verify_signature(&delegator_pubkey, &self.pubkey, &signature) {
                    Ok(_) => {
                        // Check conditions
                        if let Some(kind) = conditions.kind {
                            if self.kind != kind {
                                return EventDelegation::InvalidDelegation(
                                    "Event Kind not delegated".to_owned(),
                                );
                            }
                        }
                        if let Some(created_after) = conditions.created_after {
                            if self.created_at < created_after {
                                return EventDelegation::InvalidDelegation(
                                    "Event created before delegation started".to_owned(),
                                );
                            }
                        }
                        if let Some(created_before) = conditions.created_before {
                            if self.created_at > created_before {
                                return EventDelegation::InvalidDelegation(
                                    "Event created after delegation ended".to_owned(),
                                );
                            }
                        }
                        return EventDelegation::DelegatedBy(delegator_pubkey);
                    }
                    Err(e) => {
                        return EventDelegation::InvalidDelegation(format!("{e}"));
                    }
                }
            }
        }

        EventDelegation::NotDelegated
    }

    /// If the event came through a proxy, get the (Protocol, Id)
    pub fn proxy(&self) -> Option<(&str, &str)> {
        for t in self.tags.iter() {
            if let Tag::Other { tag, data } = t {
                if tag == "proxy" && data.len() >= 2 {
                    return Some((&data[1], &data[0]));
                }
            }
        }
        None
    }

    /// If a gift wrap event, unwrap and return the inner Rumor
    pub fn giftwrap_unwrap(&self, privkey: &PrivateKey) -> Result<Rumor, Error> {
        if self.kind != EventKind::GiftWrap {
            return Err(Error::WrongEventKind);
        }

        // Verify you are tagged
        let pkhex: PublicKeyHex = privkey.public_key().into();
        let mut tagged = false;
        for t in self.tags.iter() {
            if let Tag::Pubkey { pubkey, .. } = t {
                if *pubkey == pkhex {
                    tagged = true;
                }
            }
        }
        if !tagged {
            return Err(Error::InvalidRecipient);
        }

        // Decrypt the content
        let content = privkey.decrypt_nip44(&self.pubkey, &self.content)?;

        // Translate into a seal Event
        let seal: Event = serde_json::from_str(&content)?;

        // Verify it is a Seal
        if seal.kind != EventKind::Seal {
            return Err(Error::WrongEventKind);
        }

        // Note the author
        let author = seal.pubkey;

        // Decrypt the content
        let content = privkey.decrypt_nip44(&seal.pubkey, &seal.content)?;

        // Translate into a Rumor
        let rumor: Rumor = serde_json::from_str(&content)?;

        // Compae the author
        if rumor.pubkey != author {
            return Err(Error::InvalidPublicKey);
        }

        // Return the Rumor
        Ok(rumor)
    }
}

// Direct access into speedy-serialized bytes, to avoid alloc-deserialize just to peek
// at one of these fields
#[cfg(feature = "speedy")]
impl Event {
    /// Read the ID of the event from a speedy encoding without decoding
    /// (zero allocation)
    ///
    /// Note this function is fragile, if the Event structure is reordered,
    /// or if speedy code changes, this will break.  Neither should happen.
    pub fn get_id_from_speedy_bytes(bytes: &[u8]) -> Option<Id> {
        if bytes.len() < 32 {
            None
        } else {
            if let Ok(arr) = <[u8; 32]>::try_from(&bytes[0..32]) {
                Some(unsafe { std::mem::transmute(arr) })
            } else {
                None
            }
        }
    }

    /// Read the pubkey of the event from a speedy encoding without decoding
    /// (close to zero allocation, VerifyingKey does stuff I didn't check)
    ///
    /// Note this function is fragile, if the Event structure is reordered,
    /// or if speedy code changes, this will break.  Neither should happen.
    pub fn get_pubkey_from_speedy_bytes(bytes: &[u8]) -> Option<PublicKey> {
        if bytes.len() < 64 {
            None
        } else {
            PublicKey::from_bytes(&bytes[32..64], false).ok()
        }
    }

    /// Read the created_at of the event from a speedy encoding without decoding
    /// (zero allocation)
    ///
    /// Note this function is fragile, if the Event structure is reordered,
    /// or if speedy code changes, this will break.  Neither should happen.
    pub fn get_created_at_from_speedy_bytes(bytes: &[u8]) -> Option<Unixtime> {
        if bytes.len() < 72 {
            None
        } else if let Ok(i) = i64::read_from_buffer(&bytes[64..72]) {
            Some(Unixtime(i))
        } else {
            None
        }
    }

    /// Read the kind of the event from a speedy encoding without decoding
    /// (zero allocation)
    ///
    /// Note this function is fragile, if the Event structure is reordered,
    /// or if speedy code changes, this will break.  Neither should happen.
    pub fn get_kind_from_speedy_bytes(bytes: &[u8]) -> Option<EventKind> {
        if bytes.len() < 76 {
            None
        } else if let Ok(u) = u32::read_from_buffer(&bytes[72..76]) {
            Some(u.into())
        } else {
            None
        }
    }

    // Read the sig of the event from a speedy encoding without decoding
    // (offset would be 76..140

    /// Read the ots of the event from a speedy encoding without decoding
    /// (zero allocation)
    ///
    /// Note this function is fragile, if the Event structure is reordered,
    /// or if speedy code changes, this will break.  Neither should happen.
    pub fn get_ots_from_speedy_bytes<'a>(bytes: &'a [u8]) -> Option<&'a str> {
        if bytes.len() < 140 {
            None
        } else if bytes[140] == 0 {
            None
        } else if bytes.len() < 145 {
            None
        } else {
            let len = u32::from_ne_bytes(bytes[141..145].try_into().unwrap());
            unsafe {
                Some(std::str::from_utf8_unchecked(
                    &bytes[146..146 + len as usize],
                ))
            }
        }
    }

    /// Read the content of the event from a speedy encoding without decoding
    /// (zero allocation)
    ///
    /// Note this function is fragile, if the Event structure is reordered,
    /// or if speedy code changes, this will break.  Neither should happen.
    pub fn get_content_from_speedy_bytes<'a>(bytes: &'a [u8]) -> Option<&'a str> {
        let start = if bytes.len() < 145 {
            return None;
        } else if bytes[140] == 0 {
            141
        } else {
            // get OTS length and move past it
            let len = u32::from_ne_bytes(bytes[141..145].try_into().unwrap());
            141 + 4 + len as usize
        };

        let len = u32::from_ne_bytes(bytes[start..start + 4].try_into().unwrap());

        unsafe {
            Some(std::str::from_utf8_unchecked(
                &bytes[start + 4..start + 4 + len as usize],
            ))
        }
    }

    /// Check if any human-readable tag matches the Regex in the speedy encoding
    /// without decoding the whole thing (because our Tag representation is so complicated,
    /// we do deserialize the tags for now)
    ///
    /// Note this function is fragile, if the Event structure is reordered,
    /// or if speedy code changes, this will break.  Neither should happen.
    pub fn tag_search_in_speedy_bytes(bytes: &[u8], re: &Regex) -> Result<bool, Error> {
        if bytes.len() < 145 {
            return Ok(false);
        }

        // skip OTS
        let mut offset = if bytes[140] == 0 {
            141
        } else {
            // get OTS length and move past it
            let len = u32::from_ne_bytes(bytes[141..145].try_into().unwrap());
            141 + 4 + len as usize
        };

        // skip content
        let len = u32::from_ne_bytes(bytes[offset..offset + 4].try_into().unwrap());
        offset += 4 + len as usize;

        // Deserialize the tags
        let tags: Vec<Tag> = Vec::<Tag>::read_from_buffer(&bytes[offset..])?;

        // Search through them
        for tag in &tags {
            match tag {
                Tag::ContentWarning { warning, .. } => {
                    if re.is_match(warning.as_ref()) {
                        return Ok(true);
                    }
                }
                Tag::Hashtag { hashtag, .. } => {
                    if re.is_match(hashtag.as_ref()) {
                        return Ok(true);
                    }
                }
                Tag::Subject { subject, .. } => {
                    if re.is_match(subject.as_ref()) {
                        return Ok(true);
                    }
                }
                Tag::Title { title, .. } => {
                    if re.is_match(title.as_ref()) {
                        return Ok(true);
                    }
                }
                Tag::Other { tag, data } => {
                    if tag == "summary" && data.len() > 0 && re.is_match(data[0].as_ref()) {
                        return Ok(true);
                    }
                }
                _ => {}
            }
        }

        Ok(false)
    }
}

impl From<Event> for Rumor {
    fn from(e: Event) -> Rumor {
        Rumor {
            id: e.id,
            pubkey: e.pubkey,
            created_at: e.created_at,
            kind: e.kind,
            content: e.content,
            tags: e.tags,
        }
    }
}

impl From<Rumor> for PreEvent {
    fn from(r: Rumor) -> PreEvent {
        PreEvent {
            pubkey: r.pubkey,
            created_at: r.created_at,
            kind: r.kind,
            content: r.content,
            tags: r.tags,
        }
    }
}

impl TryFrom<PreEvent> for Rumor {
    type Error = Error;
    fn try_from(e: PreEvent) -> Result<Rumor, Error> {
        Rumor::new(e)
    }
}

#[inline]
fn get_leading_zero_bits(bytes: &[u8]) -> u8 {
    let mut res = 0_u8;
    for b in bytes {
        if *b == 0 {
            res += 8;
        } else {
            res += b.leading_zeros() as u8;
            return res;
        }
    }
    res
}

#[cfg(test)]
mod test {
    use crate::types::*;

    test_serde! {Event, test_event_serde}

    #[test]
    fn test_event_new_and_verify() {
        let privkey = PrivateKey::mock();
        let pubkey = privkey.public_key();
        let preevent = PreEvent {
            pubkey,
            created_at: Unixtime::mock(),
            kind: EventKind::TextNote,
            tags: vec![Tag::Event {
                id: Id::mock(),
                recommended_relay_url: Some(UncheckedUrl::mock()),
                marker: None,
                trailing: Vec::new(),
            }],
            content: "Hello World!".to_string(),
        };
        let mut event = Event::new(preevent, &privkey).unwrap();
        assert!(event.verify(None).is_ok());

        // Now make sure it fails when the message has been modified
        event.content = "I'm changing this message".to_string();
        let result = event.verify(None);
        assert!(result.is_err());

        // Change it back
        event.content = "Hello World!".to_string();
        let result = event.verify(None);
        assert!(result.is_ok());

        // Tweak the id only
        event.id = Id([
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 31,
        ]);
        let result = event.verify(None);
        assert!(result.is_err());
    }

    // helper
    fn create_event_with_delegation(delegator_privkey: PrivateKey, created_at: Unixtime) -> Event {
        let privkey = PrivateKey::mock();
        let pubkey = privkey.public_key();
        let delegator_pubkey = delegator_privkey.public_key();
        let conditions = DelegationConditions::try_from_str(
            "kind=1&created_at>1680000000&created_at<1680050000",
        )
        .unwrap();
        let sig = conditions
            .generate_signature(
                PublicKeyHex::try_from_str(&pubkey.as_hex_string()).unwrap(),
                delegator_privkey,
            )
            .unwrap();
        let preevent = PreEvent {
            pubkey,
            created_at,
            kind: EventKind::TextNote,
            tags: vec![
                Tag::Event {
                    id: Id::mock(),
                    recommended_relay_url: Some(UncheckedUrl::mock()),
                    marker: None,
                    trailing: Vec::new(),
                },
                Tag::Delegation {
                    pubkey: PublicKeyHex::try_from_string(delegator_pubkey.as_hex_string())
                        .unwrap(),
                    conditions,
                    sig,
                    trailing: Vec::new(),
                },
            ],
            content: "Hello World!".to_string(),
        };
        Event::new(preevent, &privkey).unwrap()
    }

    #[test]
    fn test_event_with_delegation_ok() {
        let delegator_privkey = PrivateKey::mock();
        let delegator_pubkey = delegator_privkey.public_key();
        let event = create_event_with_delegation(delegator_privkey, Unixtime(1680000012));
        assert!(event.verify(None).is_ok());

        // check delegation
        if let EventDelegation::DelegatedBy(pk) = event.delegation() {
            // expected type, check returned delegator key
            assert_eq!(pk, delegator_pubkey);
        } else {
            panic!("Expected DelegatedBy result, got {:?}", event.delegation());
        }
    }

    #[test]
    fn test_event_with_delegation_invalid_created_after() {
        let delegator_privkey = PrivateKey::mock();
        let event = create_event_with_delegation(delegator_privkey, Unixtime(1690000000));
        assert!(event.verify(None).is_ok());

        // check delegation
        if let EventDelegation::InvalidDelegation(reason) = event.delegation() {
            // expected type, check returned delegator key
            assert_eq!(reason, "Event created after delegation ended");
        } else {
            panic!(
                "Expected InvalidDelegation result, got {:?}",
                event.delegation()
            );
        }
    }

    #[test]
    fn test_event_with_delegation_invalid_created_before() {
        let delegator_privkey = PrivateKey::mock();
        let event = create_event_with_delegation(delegator_privkey, Unixtime(1610000000));
        assert!(event.verify(None).is_ok());

        // check delegation
        if let EventDelegation::InvalidDelegation(reason) = event.delegation() {
            // expected type, check returned delegator key
            assert_eq!(reason, "Event created before delegation started");
        } else {
            panic!(
                "Expected InvalidDelegation result, got {:?}",
                event.delegation()
            );
        }
    }

    #[test]
    fn test_realworld_event_with_naddr_tag() {
        let raw = r##"{"id":"7760408f6459b9546c3a4e70e3e56756421fba34526b7d460db3fcfd2f8817db","pubkey":"460c25e682fda7832b52d1f22d3d22b3176d972f60dcdc3212ed8c92ef85065c","created_at":1687616920,"kind":1,"tags":[["p","1bc70a0148b3f316da33fe3c89f23e3e71ac4ff998027ec712b905cd24f6a411","","mention"],["a","30311:1bc70a0148b3f316da33fe3c89f23e3e71ac4ff998027ec712b905cd24f6a411:1687612774","","mention"]],"content":"Watching Karnage's stream to see if I learn something about design. \n\nnostr:naddr1qq9rzd3cxumrzv3hxu6qygqmcu9qzj9n7vtd5vl78jyly037wxkyl7vcqflvwy4eqhxjfa4yzypsgqqqwens0qfplk","sig":"dbc5d05a24bfe990a1faaedfcb81a98940d86a105711dbdad9145d05b0ad0f46e3e24eaa3fc283818f27e057fe836a029fd9a68e7f1de06ff477493199d64064"}"##;
        let _: Event = serde_json::from_str(&raw).unwrap();
    }

    #[cfg(feature = "speedy")]
    #[test]
    fn test_speedy_encoded_direct_field_access() {
        use speedy::Writable;

        let privkey = PrivateKey::mock();
        let pubkey = privkey.public_key();
        let preevent = PreEvent {
            pubkey,
            created_at: Unixtime(1680000012),
            kind: EventKind::TextNote,
            tags: vec![
                Tag::Event {
                    id: Id::mock(),
                    recommended_relay_url: Some(UncheckedUrl::mock()),
                    marker: None,
                    trailing: Vec::new(),
                },
                Tag::Hashtag {
                    hashtag: "foodstr".to_string(),
                    trailing: Vec::new(),
                },
            ],
            content: "Hello World!".to_string(),
        };
        let event = Event::new(preevent, &privkey).unwrap();
        let bytes = event.write_to_vec().unwrap();

        let id = Event::get_id_from_speedy_bytes(&bytes).unwrap();
        assert_eq!(id, event.id);

        let pubkey = Event::get_pubkey_from_speedy_bytes(&bytes).unwrap();
        assert_eq!(pubkey, event.pubkey);

        let created_at = Event::get_created_at_from_speedy_bytes(&bytes).unwrap();
        assert_eq!(created_at, Unixtime(1680000012));

        let kind = Event::get_kind_from_speedy_bytes(&bytes).unwrap();
        assert_eq!(kind, event.kind);

        let ots = Event::get_ots_from_speedy_bytes(&bytes);
        assert_eq!(ots, None);

        let content = Event::get_content_from_speedy_bytes(&bytes);
        assert_eq!(content, Some(&*event.content));

        let re = regex::Regex::new("foodstr").unwrap();
        let found_foodstr = Event::tag_search_in_speedy_bytes(&bytes, &re).unwrap();
        assert!(found_foodstr);

        // Print to work out encoding
        //   test like this to see printed data:
        //   cargo test --features=speedy test_speedy_encoded_direct_field_access -- --nocapture
        println!("EVENT BYTES: {:?}", bytes);
        println!("ID: {:?}", event.id.0);
        println!("PUBKEY: {:?}", event.pubkey.as_slice());
        println!("CREATED AT: {:?}", event.created_at.0.to_ne_bytes());
        let kind32: u32 = event.kind.into();
        println!("KIND: {:?}", kind32.to_ne_bytes());
        println!("SIG: {:?}", event.sig.0.as_ref());
        if let Some(ots) = event.ots {
            println!("OTS: [1, then] {:?}", ots.as_bytes());
        } else {
            println!("OTS: [0]");
        }
        println!(
            "CONTENT: [len={:?}] {:?}",
            (event.content.as_bytes().len() as u32).to_ne_bytes(),
            event.content.as_bytes()
        );
        println!("TAGS: [len={:?}]", (event.tags.len() as u32).to_ne_bytes());

        //2, 0, 0, 0, -- one tags
        //  3, 0, 0, 0, -- Enum Variant #3
        //    93, 246, 75, 51, 48, 61, 98, 175, 199, 153, 189, 195, 109, 23, 140, 7, 178, 225, 240, 216, 36, 243, 27, 125, 200, 18, 33, 148, 64, 175, 250, 182, -- Id
        //       1, -- recommended_relay_url Option<UncheckedUrl is Some
        //           19, 0, 0, 0, -- string is 19 chars long
        //                47, 104, 111, 109, 101, 47, 117, 115, 101, 114, 47, 102, 105, 108, 101, 46, 116, 120, 116, -- "/home/user/file.txt"
        //       0, -- marker Option<String> is None
        //       0, 0, 0, 0 -- trailing Vec<String> is empty
        //  ...
    }

    #[test]
    fn test_event_gift_wrap() {
        let sec1 = PrivateKey::try_from_hex_string(
            "0000000000000000000000000000000000000000000000000000000000000001",
        )
        .unwrap();

        let sec2 = PrivateKey::try_from_hex_string(
            "0000000000000000000000000000000000000000000000000000000000000002",
        )
        .unwrap();

        let pre = PreEvent {
            pubkey: sec1.public_key(),
            created_at: Unixtime(1692_000_000),
            kind: EventKind::TextNote,
            content: "Hey man, this rocks! Please reply for a test.".to_string(),
            tags: vec![],
        };

        let gift_wrap = pre
            .clone()
            .into_gift_wrap(&sec1, &sec2.public_key())
            .unwrap();

        let rumor = gift_wrap.giftwrap_unwrap(&sec2).unwrap();
        let output_pre: PreEvent = rumor.into();

        assert_eq!(pre, output_pre);
    }

    #[test]
    fn test_effective_event_kind() {
        let raw = r#"{"id":"47074e65e6056d487dce92a12a58385b0bb73ae8de405f5f6b196bb0b89132c4","pubkey":"fa984bd7dbb282f07e16e7ae87b26a2a7b9b90b7246a44771f0cf5ae58018f52","created_at":1697312520,"kind":16,"sig":"d33eb210a32ca07252549ab582f1b2b4e02b67949884f9b29d3625914debd2b5abe819a4cdbf410e2a51c75f82e95d7e876f625620f35b998e8ed2bc4207c425","content":"","tags":[["a","30023:6389be6491e7b693e9f368ece88fcd145f07c068d2c1bbae4247b9b5ef439d32:283946"],["p","6389be6491e7b693e9f368ece88fcd145f07c068d2c1bbae4247b9b5ef439d32"],["k","30023"]]}"#;
        let e: Event = serde_json::from_str(&raw).unwrap();

        assert_ne!(e.kind, e.effective_kind());
        assert_eq!(e.effective_kind(), EventKind::LongFormContent);
    }
}
