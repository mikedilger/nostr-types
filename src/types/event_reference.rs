use super::{EventAddr, Id, PublicKey, RelayUrl};
use serde::{Deserialize, Serialize};
use std::hash::{Hash, Hasher};

/// A reference to another event, either by `Id` (often coming from an 'e' tag),
/// or by `EventAddr` (often coming from an 'a' tag).
#[derive(Clone, Debug, Serialize, Deserialize)]
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

impl PartialEq for EventReference {
    fn eq(&self, other: &Self) -> bool {
        match self {
            EventReference::Id { id: id1, .. } => {
                match other {
                    EventReference::Id { id: id2, .. } => {
                        // We don't compare the other fields which are only helpers,
                        // not definitive identity
                        id1 == id2
                    }
                    _ => false,
                }
            }
            EventReference::Addr(addr1) => match other {
                EventReference::Addr(addr2) => addr1 == addr2,
                _ => false,
            },
        }
    }
}

impl Eq for EventReference {}

impl Hash for EventReference {
    fn hash<H: Hasher>(&self, state: &mut H) {
        match self {
            EventReference::Id { id, .. } => {
                // We do not hash the other fields which are only helpers,
                // not definitive identity
                id.hash(state);
            }
            EventReference::Addr(addr) => {
                addr.hash(state);
            }
        }
    }
}
