use super::{EventKind, Id, PublicKey, Signature, Tag, Unixtime};

/// The main event type
#[derive(Clone, Debug, Eq, PartialEq)]
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
    pub ots: Option<String>,
    /// The signature of the event, which cryptographically verifies that the holder of
    /// the PrivateKey matching the event's PublicKey generated (or authorized) this event.
    /// The signature is taken over the id field only, but the id field is taken over
    /// the rest of the event data.
    pub sig: Signature,
}
