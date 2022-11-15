use derive_more::{AsMut, AsRef, Deref, From, Into};
use serde::{Deserialize, Serialize};

/// An integer count of the number of seconds from 1st January 1970.
/// This does not count any of the leap seconds that have occurred, it
/// simply presumes UTC never had leap seconds; yet it is well known
/// and well understood.
#[derive(
    AsMut,
    AsRef,
    Clone,
    Copy,
    Debug,
    Deref,
    Deserialize,
    Eq,
    From,
    Into,
    Ord,
    PartialEq,
    PartialOrd,
    Serialize,
)]
pub struct Unixtime(pub i64);
