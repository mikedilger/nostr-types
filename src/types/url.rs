use crate::error::Error;
use serde::{Deserialize, Serialize};
use std::fmt;

/// A string that is supposed to represent a URL but which might be invalid
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, PartialOrd, Serialize, Ord)]
pub struct UncheckedUrl(pub String);

impl fmt::Display for UncheckedUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl UncheckedUrl {
    /// Create an UncheckedUrl from a &str
    // note - this from_str cannot error, so we don't impl std::str::FromStr which by
    //        all rights should be called TryFromStr anyway
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> UncheckedUrl {
        UncheckedUrl(s.to_owned())
    }

    /// Create an UncheckedUrl from a String
    pub fn from_string(s: String) -> UncheckedUrl {
        UncheckedUrl(s)
    }

    /// As &str
    pub fn as_str(&self) -> &str {
        &self.0
    }

    // Mock data for testing
    #[allow(dead_code)]
    pub(crate) fn mock() -> UncheckedUrl {
        UncheckedUrl("/home/user/file.txt".to_string())
    }
}

/// A String representing a valid URL with a scheme and authority present.
/// We don't serialize/deserialize these directly, see `UncheckedUrl` for that
#[derive(Clone, Debug, Eq, Hash, PartialEq, PartialOrd, Ord)]
pub struct Url(pub String);

impl fmt::Display for Url {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Url {
    /// Create a new Url from an UncheckedUrl
    pub fn try_from_unchecked_url(u: &UncheckedUrl) -> Result<Url, Error> {
        Url::try_from_str(&u.0)
    }

    /// Create a new Url from a string
    pub fn try_from_str(s: &str) -> Result<Url, Error> {
        // We use http::Uri parse to validate
        let uri = s.trim().parse::<http::Uri>()?;
        if uri.scheme().is_none() {
            return Err(Error::InvalidUrlMissingScheme);
        }
        match uri.authority() {
            None => return Err(Error::InvalidUrlMissingAuthority),
            Some(auth) => {
                // This is an INCOMPLETE list of bad hosts
                let host = auth.host();
                if host != host.trim()
                    || host.starts_with("localhost")
                    || host.starts_with("127.")
                    || host.starts_with("[::1/")
                    || host.starts_with("[0:")
                {
                    return Err(Error::InvalidUrlHost(host.to_owned()));
                }
            }
        }

        // We use http::Uri Display trait to canonicalize
        Ok(Url(format!("{}", uri)))
    }

    /// Convert into a UncheckedUrl
    pub fn to_unchecked_url(&self) -> UncheckedUrl {
        UncheckedUrl(self.0.clone())
    }

    /// As &str
    pub fn as_str(&self) -> &str {
        &self.0
    }

    // Mock data for testing
    #[allow(dead_code)]
    pub(crate) fn mock() -> Url {
        Url("http://example.com/avatar.png".to_string())
    }
}

/// A Url validated as a nostr relay url in canonical form
/// We don't serialize/deserialize these directly, see `UncheckedUrl` for that
#[derive(Clone, Debug, Eq, Hash, PartialEq, PartialOrd, Ord)]
pub struct RelayUrl(pub String);

impl fmt::Display for RelayUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl RelayUrl {
    /// Create a new RelayUrl from a Url
    pub fn try_from_url(u: &Url) -> Result<RelayUrl, Error> {
        // Trim trailing slash if any
        let mut s = u.0.clone();
        while s.ends_with('/') {
            let _ = s.pop();
        }

        let uri = s.parse::<http::Uri>()?;

        if let Some(scheme) = uri.scheme() {
            // Verify the scheme is websockets
            if scheme.as_str() != "wss" && scheme.as_str() != "ws" {
                return Err(Error::InvalidUrlScheme(scheme.as_str().to_owned()));
            }
        } else {
            return Err(Error::InvalidUrlMissingScheme);
        }

        Ok(RelayUrl(s))
    }

    /// Create a new RelayUrl from an UncheckedUrl
    pub fn try_from_unchecked_url(u: &UncheckedUrl) -> Result<RelayUrl, Error> {
        Self::try_from_str(&u.0)
    }

    /// Construct a new RelayUrl from a Url
    pub fn try_from_str(s: &str) -> Result<RelayUrl, Error> {
        let url = Url::try_from_str(s)?;
        RelayUrl::try_from_url(&url)
    }

    /// Convert into a Url
    pub fn to_url(&self) -> Url {
        Url(self.0.clone())
    }

    /// Convert into a UncheckedUrl
    pub fn to_unchecked_url(&self) -> UncheckedUrl {
        UncheckedUrl(self.0.clone())
    }

    /// As &str
    pub fn as_str(&self) -> &str {
        &self.0
    }

    // Mock data for testing
    #[allow(dead_code)]
    pub(crate) fn mock() -> Url {
        Url("wss://example.com".to_string())
    }
}

impl TryFrom<Url> for RelayUrl {
    type Error = Error;

    fn try_from(u: Url) -> Result<RelayUrl, Error> {
        RelayUrl::try_from_url(&u)
    }
}

impl TryFrom<&Url> for RelayUrl {
    type Error = Error;

    fn try_from(u: &Url) -> Result<RelayUrl, Error> {
        RelayUrl::try_from_url(u)
    }
}

impl From<RelayUrl> for Url {
    fn from(ru: RelayUrl) -> Url {
        ru.to_url()
    }
}

#[cfg(test)]
mod test {
    use super::*;

    test_serde! {UncheckedUrl, test_unchecked_url_serde}
}
