use super::{EventKind, Id, PublicKey, Unixtime};
use serde::{Deserialize, Serialize};

/// Filters which specify what events a client is looking for
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Filters {
    /// Events which match these ids
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[serde(default)]
    pub ids: Vec<String>,

    /// Events which match these authors
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[serde(default)]
    pub authors: Vec<String>, // public key prefix

    /// Events which match these kinds
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[serde(default)]
    pub kinds: Vec<EventKind>,

    /// Events when referenced in an 'e' tag
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[serde(default)]
    pub e: Vec<Id>,

    /// Events when referenced in a 'p' tag
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[serde(default)]
    pub p: Vec<PublicKey>,

    /// Events occuring after this date
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub since: Option<Unixtime>,

    /// Events occuring before this date
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub until: Option<Unixtime>,

    /// A limit on the number of events to return in the initial query
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub limit: Option<usize>,
}

impl Filters {
    // Mock data for testing
    #[allow(dead_code)]
    pub(crate) fn mock() -> Filters {
        Filters {
            ids: vec!["21345".to_string()],
            authors: vec![],
            kinds: vec![EventKind::TextNote, EventKind::Metadata],
            e: vec![],
            p: vec![],
            since: Some(Unixtime::mock()),
            until: None,
            limit: None,
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    test_serde! {Filters, test_filters_serde}
}
