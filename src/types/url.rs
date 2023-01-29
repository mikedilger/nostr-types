use crate::error::Error;
use serde::de::{Deserializer, Visitor};
use serde::ser::Serializer;
use serde::{Deserialize, Serialize};
use std::fmt;

/// A String representing a Url with a notion of whether it is a valid nostr URL or not
///
/// This Serializes/Deserializes from a string
#[derive(Clone, Debug, Eq, Hash, PartialEq, PartialOrd, Ord)]
pub struct Url(String, bool);

impl fmt::Display for Url {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Url {
    /// Create a new Url from a string
    pub fn new(s: &str) -> Url {
        Url(s.to_owned(), s.parse::<http::Uri>().is_ok())
    }

    // Get URL string in canonical form, or Err with the original
    fn canonical_str(&self) -> Result<String, Error> {
        // Must be a valid URL
        if !self.1 {
            return Err(Error::Url(self.0.clone()));
        }

        // Clean it up
        let mut s = self.0.trim().to_lowercase();
        if s.ends_with('/') {
            s = s.trim_end_matches('/').to_string();
        }

        // Must be a valid Relay URL
        match Self::is_valid_relay_url_str(&s) {
            true => Ok(s),
            false => Err(Error::Url(s)),
        }
    }

    /// Check if the URL is a valid relay URL
    pub fn is_valid_relay_url(&self) -> bool {
        Self::is_valid_relay_url_str(&self.0)
    }

    fn is_valid_relay_url_str(s: &str) -> bool {
        if let Ok(uri) = s.parse::<http::Uri>() {
            if let Some(scheme) = uri.scheme() {
                if scheme.as_str() == "wss" || scheme.as_str() == "ws" {
                    if let Some(authority) = uri.authority() {
                        let host = authority.host();
                        if host == host.trim()
                            && !host.starts_with("localhost")
                            && !host.starts_with("127.")
                            && !host.starts_with("[::1/")
                            && !host.starts_with("[0:")
                        {
                            return true;
                        }
                    }
                }
            }
        }
        false
    }

    /// If the Url represents a valid URL
    pub fn is_valid(&self) -> bool {
        self.1
    }

    // Mock data for testing
    #[allow(dead_code)]
    pub(crate) fn mock() -> Url {
        Url("wss://example.com".to_string(), true)
    }
}

impl Serialize for Url {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // just serialize the string part. the valid part can be recomputed.
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for Url {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_str(UrlVisitor)
    }
}

struct UrlVisitor;

impl Visitor<'_> for UrlVisitor {
    type Value = Url;

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "a string representing a nostr URL")
    }

    fn visit_str<E>(self, v: &str) -> Result<Url, E>
    where
        E: serde::de::Error,
    {
        Ok(Url::new(v))
    }
}

/// A Url validated as a nostr relay url in canonical form
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, PartialOrd, Serialize, Ord)]
pub struct RelayUrl(pub String);

impl TryFrom<Url> for RelayUrl {
    type Error = Error;

    fn try_from(u: Url) -> Result<RelayUrl, Error> {
        Ok(RelayUrl(u.canonical_str()?))
    }
}

impl TryFrom<&Url> for RelayUrl {
    type Error = Error;

    fn try_from(u: &Url) -> Result<RelayUrl, Error> {
        Ok(RelayUrl(u.canonical_str()?))
    }
}

impl From<RelayUrl> for Url {
    fn from(ru: RelayUrl) -> Url {
        Url(ru.0, true)
    }
}

impl fmt::Display for RelayUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    test_serde! {Url, test_url_serde}
}
