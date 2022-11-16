use super::{EventKind, Id, Metadata, PrivateKey, PublicKey, Signature, Tag, Unixtime};
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
    pub fn new(input: PreEvent, privkey: PrivateKey) -> Result<Event, Error> {
        use rand_core::RngCore;

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

        // Signature
        let mut rand: [u8; 32] = [0; 32];
        rand_core::OsRng.fill_bytes(&mut rand);
        let signature = privkey.try_sign_prehashed(&id, &rand)?;

        Ok(Event {
            id: Id(id),
            pubkey: input.pubkey,
            created_at: input.created_at,
            kind: input.kind,
            tags: input.tags,
            content: input.content,
            ots: input.ots,
            sig: Signature(signature),
        })
    }

    /// Check the validity of an event. This is useful if you deserialize an event
    /// from the network. If you create an event using new() it should already be
    /// trustworthy.
    pub fn verify(&self) -> Result<(), Error> {
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
        Event::new(pre, private_key).unwrap()
    }

    /// Create an event that sets Metadata
    pub fn new_set_metadata(
        mut input: PreEvent,
        privkey: PrivateKey,
        name: String,
        about: String,
        picture: String,
    ) -> Result<Event, Error> {
        input.kind = EventKind::Metadata;
        let metadata = Metadata {
            name,
            about,
            picture,
        };
        input.content = serde_json::to_string(&metadata)?;
        Event::new(input, privkey)
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
            tags: vec![Tag::Event(vec![
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f".to_string(),
                "https://example.com".to_string(),
            ])],
            content: "Hello World!".to_string(),
            ots: None,
        };
        let mut event = Event::new(preevent, privkey.clone()).unwrap();
        assert!(event.verify().is_ok());

        // Now make sure it fails when the message has been modified
        event.content = "I'm changing this message".to_string();
        let result = event.verify();
        assert!(result.is_err());

        // Change it back
        event.content = "Hello World!".to_string();
        let result = event.verify();
        assert!(result.is_ok());

        // Tweak the id only
        event.id = Id([
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 31,
        ]);
        let result = event.verify();
        assert!(result.is_err());
    }
}
