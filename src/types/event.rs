use super::{
    EventKind, Id, Metadata, PrivateKey, PublicKey, PublicKeyHex, RelayUrl, Signature, Tag,
    Unixtime,
};
use crate::Error;
use base64::Engine;
use k256::sha2::{Digest, Sha256};
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::thread::JoinHandle;

/// The main event type
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Event {
    /// The Id of the event, generated as a SHA256 of the inner event data
    pub id: Id,

    /// The public key of the actor who created the event
    pub pubkey: PublicKey,

    /// The (unverified) time at which the event was created
    pub created_at: Unixtime,

    /// The kind of event
    pub kind: EventKind,

    /// A set of tags that apply to the event
    pub tags: Vec<Tag>,

    /// The content of the event
    pub content: String,

    /// An optional verified time for the event (using OpenTimestamp)
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub ots: Option<String>,

    /// The signature of the event, which cryptographically verifies that the holder of
    /// the PrivateKey matching the event's PublicKey generated (or authorized) this event.
    /// The signature is taken over the id field only, but the id field is taken over
    /// the rest of the event data.
    pub sig: Signature,
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
#[derive(Clone, Debug)]
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
    /// An optional verified time for the event (using OpenTimestamp)
    pub ots: Option<String>,
}

impl PreEvent {
    /// Create a NIP-04 EncryptedDirectMessage PreEvent.
    ///
    /// Note that this creates the 'p' tag, but does not add a recommended_relay_url to it,
    /// so the caller should handle that.
    pub fn new_nip04(
        private_key: &PrivateKey,
        recipient_public_key: PublicKey,
        message: &str,
    ) -> Result<PreEvent, Error> {
        let input: &[u8] = message.as_bytes();
        let (iv, ciphertext) = private_key.nip04_encrypt(&recipient_public_key, input)?;
        let content = format!(
            "{}?iv={}",
            base64::engine::general_purpose::STANDARD.encode(ciphertext),
            base64::engine::general_purpose::STANDARD.encode(iv)
        );

        Ok(PreEvent {
            pubkey: private_key.public_key(),
            created_at: Unixtime::now().unwrap(),
            kind: EventKind::EncryptedDirectMessage,
            tags: vec![Tag::Pubkey {
                pubkey: recipient_public_key.into(),
                recommended_relay_url: None, // FIXME,
                petname: None,
            }],
            content,
            ots: None,
        })
    }
}

impl Event {
    fn hash(input: &PreEvent) -> Result<Id, Error> {
        let serialized: String = serialize_inner_event!(
            &input.pubkey,
            &input.created_at,
            &input.kind,
            &input.tags,
            &input.content
        );

        // Hash
        let mut hasher = Sha256::new();
        hasher.update(serialized.as_bytes());
        let id = hasher.finalize();
        let id: [u8; 32] = id.into();
        Ok(Id(id))
    }

    /// Create a new event
    pub fn new(input: PreEvent, privkey: &PrivateKey) -> Result<Event, Error> {
        // Generate Id
        let id = Self::hash(&input)?;

        // Generate Signature
        let signature = privkey.sign_id(id)?;

        Ok(Event {
            id,
            pubkey: input.pubkey,
            created_at: input.created_at,
            kind: input.kind,
            tags: input.tags,
            content: input.content,
            ots: input.ots,
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
    ) -> Result<Event, Error> {
        let target = Some(format!("{}", zero_bits));

        // Strip any pre-existing nonce tags
        input.tags.retain(|t| !matches!(t, Tag::Nonce { .. }));

        // Add nonce tag to the end
        input.tags.push(Tag::Nonce {
            nonce: "0".to_string(),
            target: target.clone(),
        });
        let index = input.tags.len() - 1;

        let cores = num_cpus::get();

        let quitting = Arc::new(AtomicBool::new(false));
        let nonce = Arc::new(AtomicU64::new(0)); // will store the nonce that works

        let mut join_handles: Vec<JoinHandle<_>> = Vec::with_capacity(cores);

        for core in 0..cores {
            let mut attempt: u64 = core as u64 * (u64::MAX / cores as u64);
            let mut input = input.clone();
            let target = target.clone();
            let index = index;
            let quitting = quitting.clone();
            let nonce = nonce.clone();
            let zero_bits = zero_bits;
            let join_handle = thread::spawn(move || {
                loop {
                    if quitting.load(Ordering::Relaxed) {
                        break;
                    }

                    input.tags[index] = Tag::Nonce {
                        nonce: format!("{}", attempt),
                        target: target.clone(),
                    };

                    let id = Self::hash(&input).unwrap();

                    if get_leading_zero_bits(&id.0) >= zero_bits {
                        nonce.store(attempt, Ordering::Relaxed);
                        quitting.store(true, Ordering::Relaxed);
                        break;
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
        };
        let id = Self::hash(&input).unwrap();

        // Signature
        let signature = privkey.sign_id(id)?;

        Ok(Event {
            id,
            pubkey: input.pubkey,
            created_at: input.created_at,
            kind: input.kind,
            tags: input.tags,
            content: input.content,
            ots: input.ots,
            sig: signature,
        })
    }

    /// Check the validity of an event. This is useful if you deserialize an event
    /// from the network. If you create an event using new() it should already be
    /// trustworthy.
    pub fn verify(&self, maxtime: Option<Unixtime>) -> Result<(), Error> {
        use k256::schnorr::signature::Verifier;

        let serialized: String = serialize_inner_event!(
            &self.pubkey,
            &self.created_at,
            &self.kind,
            &self.tags,
            &self.content
        );

        // Verify the signature
        self.pubkey.0.verify(serialized.as_bytes(), &self.sig.0)?;

        // Also verify the ID is the SHA256
        // (the above verify function also does it internally,
        //  so there is room for improvement here)
        let mut hasher = Sha256::new();
        hasher.update(serialized.as_bytes());
        let id = hasher.finalize();

        // Optional verify that the message was in the past
        if let Some(mt) = maxtime {
            if self.created_at > mt {
                return Err(Error::EventInFuture);
            }
        }

        if *id != self.id.0 {
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
            ots: None,
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
                },
                Tag::Other {
                    tag: "relays".to_owned(),
                    data: relays,
                },
                Tag::Other {
                    tag: "amount".to_owned(),
                    data: vec![format!("{}", millisatoshis)],
                },
            ],
            content,
            ots: None,
        };

        if let Some(ze) = zapped_event {
            pre_event.tags.push(Tag::Event {
                id: ze,
                recommended_relay_url: None,
                marker: None,
            });
        }

        Event::new(pre_event, privkey)
    }

    /// If an event is an EncryptedDirectMessage, decrypt it's contents
    pub fn decrypted_contents(&self, private_key: &PrivateKey) -> Result<String, Error> {
        if self.kind != EventKind::EncryptedDirectMessage {
            return Err(Error::WrongEventKind);
        }
        let parts: Vec<&str> = self.content.split("?iv=").collect();
        if parts.len() != 2 {
            return Err(Error::BadEncryptedMessage);
        }

        let ciphertext: Vec<u8> = base64::engine::general_purpose::STANDARD.decode(parts[0])?;
        let iv_vec: Vec<u8> = base64::engine::general_purpose::STANDARD.decode(parts[1])?;
        let iv: [u8; 16] = iv_vec.try_into().unwrap();

        let decrypted_bytes = private_key.nip04_decrypt(&self.pubkey, &ciphertext, iv)?;
        let s: String = String::from_utf8_lossy(&decrypted_bytes).into();
        Ok(s)
    }

    /// If the event refers to people, get all the PublicKeys it refers to
    /// along with recommended relay URL and petname for each
    pub fn people(&self) -> Vec<(PublicKeyHex, Option<RelayUrl>, Option<String>)> {
        let mut output: Vec<(PublicKeyHex, Option<RelayUrl>, Option<String>)> = Vec::new();

        // All 'p' tags
        for tag in self.tags.iter() {
            if let Tag::Pubkey {
                pubkey,
                recommended_relay_url,
                petname,
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

    /// If the event refers to people, get all the PublicKeys it refers to
    /// along with recommended relay URL and petname for each, but only if they
    /// are referenced within the note.
    pub fn referenced_people(&self) -> Vec<(PublicKeyHex, Option<RelayUrl>, Option<String>)> {
        let mut output: Vec<(PublicKeyHex, Option<RelayUrl>, Option<String>)> = Vec::new();
        for (n, tag) in self.tags.iter().enumerate() {
            if let Tag::Pubkey {
                pubkey,
                recommended_relay_url,
                petname,
            } = tag
            {
                if self.content.contains(&format!("#[{}]", n)) {
                    output.push((
                        pubkey.to_owned(),
                        recommended_relay_url
                            .as_ref()
                            .and_then(|rru| RelayUrl::try_from_unchecked_url(rru).ok()),
                        petname.to_owned(),
                    ));
                }
            }
        }

        output
    }

    /// Is the event a reply?
    #[deprecated(since = "0.2.0", note = "please use `replies_to` instead")]
    pub fn is_reply(&self) -> bool {
        if self.kind != EventKind::TextNote {
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
        // must be a text note
        if self.kind != EventKind::TextNote {
            return None;
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
        if self.kind != EventKind::TextNote {
            return None;
        }

        // look for an 'e' tag with marker 'root'
        for tag in self.tags.iter() {
            if let Tag::Event {
                id,
                recommended_relay_url,
                marker,
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

        let num_e_tags = self
            .tags
            .iter()
            .filter(|e| matches!(e, Tag::Event { .. }))
            .count();
        if num_e_tags < 2 {
            return None;
        }

        // otherwise use the first 'e' tag if unmarked
        if let Some(Tag::Event {
            id,
            recommended_relay_url,
            marker,
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

    /// If this event replies to a thread, get all ancestors in that thread.
    /// This also gets all mentioned events.
    pub fn replies_to_ancestors(&self) -> Vec<(Id, Option<RelayUrl>)> {
        // must be a text note
        if self.kind != EventKind::TextNote {
            return vec![];
        }

        let mut output: Vec<(Id, Option<RelayUrl>)> = Vec::new();

        for tag in self.tags.iter() {
            if let Tag::Event {
                id,
                recommended_relay_url,
                marker: _,
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

        output
    }

    /// If this event mentions others, get those other event Ids
    /// and optional recommended relay Urls
    pub fn mentions(&self) -> Vec<(Id, Option<RelayUrl>)> {
        // must be a text note
        if self.kind != EventKind::TextNote {
            return vec![];
        }

        let mut output: Vec<(Id, Option<RelayUrl>)> = Vec::new();

        // Collect every 'e' tag marked as 'mention'
        for tag in self.tags.iter() {
            if let Tag::Event {
                id,
                recommended_relay_url,
                marker,
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
            marker: _,
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
            if let Tag::Event {
                id,
                recommended_relay_url: _,
                marker: _,
            } = tag
            {
                ids.push(*id);
            }
        }

        if ids.is_empty() {
            None
        } else {
            Some((ids, self.content.clone()))
        }
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
            if let Tag::Subject(sub) = tag {
                return Some(sub.clone());
            }
        }

        None
    }

    /// If this event specifies a content warning, return that subject string
    pub fn content_warning(&self) -> Option<String> {
        for tag in self.tags.iter() {
            if let Tag::ContentWarning(warn) = tag {
                return Some(warn.clone());
            }
        }

        None
    }

    /// Return all the hashtags this event refers to
    pub fn hashtags(&self) -> Vec<String> {
        if self.kind != EventKind::TextNote {
            return vec![];
        }

        let mut output: Vec<String> = Vec::new();

        for tag in self.tags.iter() {
            if let Tag::Hashtag(hash) = tag {
                output.push(hash.clone());
            }
        }

        output
    }

    /// Return all the URLs this event refers to
    pub fn urls(&self) -> Vec<RelayUrl> {
        if self.kind != EventKind::TextNote {
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
            if let Tag::Nonce { nonce: _, target } = tag {
                if let Some(t) = target {
                    target_zeroes = t.parse::<u8>().unwrap_or(0);
                }
                break;
            }
        }

        zeroes.min(target_zeroes)
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
            pubkey: pubkey.clone(),
            created_at: Unixtime::mock(),
            kind: EventKind::TextNote,
            tags: vec![Tag::Event {
                id: Id::mock(),
                recommended_relay_url: Some(UncheckedUrl::mock()),
                marker: None,
            }],
            content: "Hello World!".to_string(),
            ots: None,
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
}
