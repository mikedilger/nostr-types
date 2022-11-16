use derive_more::{AsMut, AsRef, Deref, From, FromStr, Into};
use serde::{Deserialize, Serialize};

/// A Url
#[derive(
    AsMut, AsRef, Clone, Debug, Deref, Deserialize, Eq, From, FromStr, Into, PartialEq, Serialize,
)]
pub struct Url(pub String);

impl Url {
    fn mock() -> Url {
        Url("https://example.com".to_string())
    }
}
