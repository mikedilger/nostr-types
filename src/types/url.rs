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
    Serialize,
)]
pub struct Url(pub String);

impl Url {
    /// Create a new Url from a string, if it is a valid URL
    pub fn new_validated(s: &str) -> Result<Url, Error> {
        let uri = s.parse::<http::Uri>()?;
        if let Some(scheme) = uri.scheme() {
            if scheme.as_str() == "wss" || scheme.as_str() == "ws" {
                Ok(Url(s.to_owned()))
            } else {
                Err(Error::InvalidUrlScheme(scheme.as_str().to_owned()))
            }
        } else {
            Err(Error::MissingUrlScheme)
        }
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
