use serde::{Deserialize, Serialize};

/// Metadata about a user
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Metadata {
    /// User name
    pub name: String,

    /// About the user
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub about: Option<String>,

    /// A url or other string representation of a picture of the user
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub picture: Option<String>,

    /// NIP-05
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub nip05: Option<String>,
}

impl Metadata {
    // Mock data for testing
    #[allow(dead_code)]
    pub(crate) fn mock() -> Metadata {
        Metadata {
            name: "Mike".to_owned(),
            about: Some("Just some guy".to_owned()),
            picture: None,
            nip05: None,
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    test_serde! {Metadata, test_metadata_serde}
}
