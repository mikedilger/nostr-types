use derive_more::{AsMut, AsRef, Deref, From, FromStr, Into};

/// A random client-chosen string used to refer to a subscription
#[derive(AsMut, AsRef, Clone, Debug, Deref, Eq, From, FromStr, Into, PartialEq)]
pub struct SubscriptionId(pub String);
