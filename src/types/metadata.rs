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

impl Metadata {
    // Mock data for testing
    #[allow(dead_code)]
    pub(crate) fn mock() -> Metadata {
        Metadata {
            name: "Mike".to_owned(),
            about: "Just some guy".to_owned(),
            picture: "no".to_owned(),
        }
    }
}
