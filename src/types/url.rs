use derive_more::{AsMut, AsRef, Deref, From, FromStr, Into};
use serde::{Deserialize, Serialize};

/// A Url
#[derive(
    AsMut, AsRef, Clone, Debug, Deref, Deserialize, Eq, From, FromStr, Into, PartialEq, Serialize,
)]
pub struct Url(pub String);

impl Url {
    // Mock data for testing
    #[allow(dead_code)]
    pub(crate) fn mock() -> Url {
        Url("https://example.com".to_string())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    test_serde! {Url, test_url_serde}
}
