use crate::Error;
use derive_more::{AsMut, AsRef, Deref, Display, From, FromStr, Into};
use serde::{Deserialize, Serialize};

/// A Url
#[derive(
    AsMut,
    AsRef,
    Clone,
    Debug,
    Deref,
    Deserialize,
    Display,
    Eq,
    From,
    FromStr,
    Hash,
    Into,
    PartialEq,
    PartialOrd,
    Ord,
    Serialize,
)]
pub struct Url(pub String);

impl Url {
    /// Create a new Url from a string, if it is a valid URL
    pub fn new_validated(s: &str) -> Result<Url, Error> {
        let uri = s.parse::<http::Uri>()?;

        let scheme = match uri.scheme() {
            Some(s) => s,
            None => return Err(Error::InvalidUrlMissingScheme),
        };

        if scheme.as_str() != "wss" && scheme.as_str() != "ws" {
            return Err(Error::InvalidUrlScheme(scheme.as_str().to_owned()));
        }

        let authority = match uri.authority() {
            Some(a) => a,
            None => return Err(Error::InvalidUrlMissingAuthority),
        };

        // FIXME TBD TODO: there are plenty of other invalid ones.
        let host = authority.host();
        if host != host.trim()
            || host.starts_with("localhost")
            || host.starts_with("127.")
            || host.starts_with("[::1/")
            || host.starts_with("[0:")
        {
            return Err(Error::InvalidUrlHost(host.to_owned()));
        }

        Ok(Url(s.to_owned()))
    }

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
