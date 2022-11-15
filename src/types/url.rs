use derive_more::{AsMut, AsRef, Deref, From, FromStr, Into};

/// A Url
#[derive(AsMut, AsRef, Clone, Debug, Deref, Eq, From, FromStr, Into, PartialEq)]
pub struct Url(pub String);
