use crate::Error;
use derive_more::{AsMut, AsRef, Deref, Display, From, Into};
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
    Display,
    Eq,
    From,
    Into,
    Ord,
    PartialEq,
    PartialOrd,
    Serialize,
)]
pub struct Unixtime(pub i64);

impl Unixtime {
    /// Get the current unixtime (depends on the system clock being accurate)
    pub fn now() -> Result<Unixtime, Error> {
        Ok(Unixtime(std::time::UNIX_EPOCH.elapsed()?.as_secs() as i64))
    }

    // Mock data for testing
    #[allow(dead_code)]
    pub(crate) fn mock() -> Unixtime {
        Unixtime(1668572286)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    test_serde! {Unixtime, test_unixtime_serde}

    #[test]
    fn test_print_now() {
        println!("NOW: {}", Unixtime::now().unwrap());
    }
}
