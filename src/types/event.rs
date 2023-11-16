use crate::types::{Id, MilliSatoshi, PublicKey};
use crate::versioned::event::{EventV1, PreEventV1, RumorV1};

/// The main event type
pub type Event = EventV1;

/// Data used to construct an event
pub type PreEvent = PreEventV1;

/// A Rumor is an Event without a signature
pub type Rumor = RumorV1;

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

