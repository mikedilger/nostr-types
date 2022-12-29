use super::{EventKind, Id, Metadata, PrivateKey, PublicKey, Signature, Tag, Unixtime, Url};
use crate::Error;
use k256::sha2::{Digest, Sha256};
use serde::{Deserialize, Serialize};

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
            serde_json::to_string(&$pubkey)?,
            serde_json::to_string(&$created_at)?,
            serde_json::to_string(&$kind)?,
            serde_json::to_string(&$tags)?,
            serde_json::to_string(&$content)?
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

impl Event {
    /// Create a new event
    pub fn new(input: PreEvent, privkey: &PrivateKey) -> Result<Event, Error> {
        let serialized: String = serialize_inner_event!(
            input.pubkey,
            input.created_at,
            input.kind,
            input.tags,
            input.content
        );

        // Hash
        let mut hasher = Sha256::new();
        hasher.update(serialized.as_bytes());
        let id = hasher.finalize();
        let id: [u8; 32] = id.into();
        let id: Id = Id(id);

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
            self.pubkey,
            self.created_at,
            self.kind,
            self.tags,
            self.content
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
        name: Option<String>,
        about: Option<String>,
        picture: Option<String>,
        nip05: Option<String>,
        lud16: Option<String>,
    ) -> Result<Event, Error> {
        input.kind = EventKind::Metadata;
        let metadata = Metadata {
            name,
            about,
            picture,
            nip05,
            lud16,
        };
        input.content = serde_json::to_string(&metadata)?;
        Event::new(input, privkey)
    }

    /// If the event refers to people, get all the PublicKeys it refers to
    /// along with recommended relay URL and petname for each
    pub fn people(&self) -> Vec<(PublicKey, Option<Url>, Option<String>)> {
        let mut output: Vec<(PublicKey, Option<Url>, Option<String>)> = Vec::new();

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
                    recommended_relay_url.to_owned(),
                    petname.to_owned(),
                ));
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
    pub fn replies_to(&self) -> Option<(Id, Option<Url>)> {
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
                    return Some((*id, recommended_relay_url.to_owned()));
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
                    return Some((*id, recommended_relay_url.to_owned()));
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
                return Some((*id, recommended_relay_url.to_owned()));
            }
        }

        // Otherwise there are 'e' tags but they have unrecognized markings
        // so we will not consider them as replies.

        None
    }

    /// If this event replies to a thread, get that threads root event Id if
    /// available, along with an optional recommended_relay_url
    pub fn replies_to_root(&self) -> Option<(Id, Option<Url>)> {
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
                    return Some((*id, recommended_relay_url.to_owned()));
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
                return Some((*id, recommended_relay_url.to_owned()));
            }
        }

        None
    }

    /// If this event replies to a thread, get all ancestors in that thread
    pub fn replies_to_ancestors(&self) -> Vec<(Id, Option<Url>)> {
        if self.kind != EventKind::TextNote {
            return vec![];
        }

        let mut output: Vec<(Id, Option<Url>)> = Vec::new();

        for tag in self.tags.iter() {
            if let Tag::Event {
                id,
                recommended_relay_url,
                marker: _,
            } = tag
            {
                output.push((*id, recommended_relay_url.to_owned()));
            }
        }

        output
    }

    /// If this event reacts to another, get that other event's Id,
    /// the reaction content, and an optional Recommended relay Url
    pub fn reacts_to(&self) -> Option<(Id, String, Option<Url>)> {
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
            return Some((*id, self.content.clone(), recommended_relay_url.to_owned()));
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
    pub fn urls(&self) -> Vec<Url> {
        if self.kind != EventKind::TextNote {
            return vec![];
        }

        let mut output: Vec<Url> = Vec::new();

        for tag in self.tags.iter() {
            if let Tag::Reference(reference) = tag {
                output.push(reference.clone());
            }
        }

        output
    }

    /// Get the proof-of-work count of leading bits
    pub fn pow(&self) -> usize {
        // Count leading bits in the Id field
        let mut zeroes: usize = 0;
        for byte in self.id.0 {
            if byte == 0 {
                zeroes += 8;
            } else {
                zeroes += byte.leading_zeros() as usize;
                break;
            }
        }

        // Check that they meant it
        let mut target_zeroes: usize = 0;
        for tag in self.tags.iter() {
            if let Tag::Nonce { nonce: _, target } = tag {
                if let Some(t) = target {
                    target_zeroes = t.parse::<usize>().unwrap_or(0);
                }
                break;
            }
        }

        zeroes.max(target_zeroes)
    }
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
                recommended_relay_url: Some(Url::mock()),
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
