use super::{EventAddr, Id, RelayUrl};
use serde::{Deserialize, Serialize};

/// A reference to another event, either by `Id` (often coming from an 'e' tag),
/// or by `EventAddr` (often coming from an 'a' tag).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum EventReference {
    /// Refer to a specific event by Id, optionally with a marker
    Id(Id, Option<RelayUrl>, Option<String>),

    /// Refer to a replaceable event by EventAddr
    Addr(EventAddr),
}
