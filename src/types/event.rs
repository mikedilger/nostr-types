use crate::types::{Id, MilliSatoshi, PublicKey};
use crate::versioned::event3::{EventV3, PreEventV3, RumorV3};

/// The main event type
pub type Event = EventV3;

/// Data used to construct an event
pub type PreEvent = PreEventV3;

/// A Rumor is an Event without a signature
pub type Rumor = RumorV3;

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
