use super::{EventAddr, Id, PublicKey, RelayUrl};
use serde::{Deserialize, Serialize};

/// A reference to another event, either by `Id` (often coming from an 'e' tag),
/// or by `EventAddr` (often coming from an 'a' tag).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum EventReference {
    /// Refer to a specific event by Id
    Id {
        /// The event id
        id: Id,

        /// Optionally include author (to find via their relay list)
        author: Option<PublicKey>,

        /// Optionally include relays (to find the event)
        relays: Vec<RelayUrl>,

        /// Optional marker, if this came from an event tag
        marker: Option<String>,
    },

    /// Refer to a replaceable event by EventAddr
    Addr(EventAddr),
}
