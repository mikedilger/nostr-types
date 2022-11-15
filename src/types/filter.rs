use super::{EventKind, Id, Unixtime};

/// Filters which specify what events a client is looking for
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Filters {
    /// Events which match these ids
    pub ids: Vec<String>,
    /// Events which match these authors
    pub authors: Vec<String>, // public key prefix
    /// Events which match these kinds
    pub kinds: Vec<EventKind>,
    /// Events when referenced in an 'e' tag
    pub e: Vec<Id>,
    /// Events when referenced in a 'p' tag
    pub p: Vec<Id>,
    /// Events occuring after this date
    pub since: Option<Unixtime>,
    /// Events occuring before this date
    pub until: Option<Unixtime>,
    /// A limit on the number of events to return in the initial query
    pub limit: Option<usize>,
}
