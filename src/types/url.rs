use serde::de::{Deserializer, Visitor};
use serde::ser::Serializer;
use serde::{Deserialize, Serialize};
use std::fmt;

/// A String representing a Url with a notion of whether it is a valid nostr URL or not
///
/// This Serializes/Deserializes from a string
#[derive(Clone, Debug, Eq, Hash, PartialEq, PartialOrd, Ord)]
pub struct Url(String, bool);

impl std::ops::Deref for Url {
    type Target = str;
    #[allow(clippy::explicit_auto_deref)]
    fn deref(&self) -> &Self::Target {
        &*self.0
    }
}

impl fmt::Display for Url {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Url {
    /// Create a new Url from a string
    pub fn new(s: &str) -> Url {
        let mut output = Url(s.to_owned(), false);

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
                            output.1 = true;
                        }
                    }
                }
            }
        }

        output
    }

    /// Get reference to inner string
    pub fn inner(&self) -> &str {
        &self.0
    }

    /// If the Url represents a valid nostr URL
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

#[cfg(test)]
mod test {
    use super::*;

    test_serde! {Url, test_url_serde}
}
