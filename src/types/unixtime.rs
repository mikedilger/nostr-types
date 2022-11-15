use derive_more::{AsMut, AsRef, Deref, From, Into};

/// An integer count of the number of seconds from 1st January 1970.
/// This does not count any of the leap seconds that have occurred, it
/// simply presumes UTC never had leap seconds; yet it is well known
/// and well understood.
#[derive(AsMut, AsRef, Clone, Copy, Debug, Deref, Eq, From, Into, Ord, PartialEq, PartialOrd)]
pub struct Unixtime(pub i64);
