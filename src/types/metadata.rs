use serde::{Deserialize, Serialize};

/// Metadata about a user
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Metadata {
    /// User name
    pub name: String,

    /// About the user
    pub about: String,

    /// A url or other string representation of a picture of the user
    pub picture: String,
}
