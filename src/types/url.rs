use crate::error::Error;
use serde::{Deserialize, Serialize};
#[cfg(feature = "speedy")]
use speedy::{Readable, Writable};
use std::fmt;

/// A string that is supposed to represent a URL but which might be invalid
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, PartialOrd, Serialize, Ord)]
#[cfg_attr(feature = "speedy", derive(Readable, Writable))]
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

/// A String representing a valid URL with an authority present including an
/// Internet based host.
///
/// We don't serialize/deserialize these directly, see `UncheckedUrl` for that
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[cfg_attr(feature = "speedy", derive(Readable, Writable))]
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
        // We use the url crate to parse and normalize
        let url = url::Url::parse(s.trim())?;

        if !url.has_authority() {
            return Err(Error::InvalidUrlMissingAuthority);
        }

        if let Some(host) = url.host() {
            match host {
                url::Host::Domain(_) => {
                    // Strange that we can't access as a string
                    let s = format!("{host}");
                    if s != s.trim() || s.starts_with("localhost") {
                        return Err(Error::InvalidUrlHost(s));
                    }
                }
                url::Host::Ipv4(addr) => {
                    let addrx: core_net::Ipv4Addr = unsafe { std::mem::transmute(addr) };
                    if !addrx.is_global() {
                        return Err(Error::InvalidUrlHost(format!("{host}")));
                    }
                }
                url::Host::Ipv6(addr) => {
                    let addrx: core_net::Ipv6Addr = unsafe { std::mem::transmute(addr) };
                    if !addrx.is_global() {
                        return Err(Error::InvalidUrlHost(format!("{host}")));
                    }
                }
            }
        } else {
            return Err(Error::InvalidUrlHost("".to_string()));
        }

        Ok(Url(url.as_str().to_owned()))
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
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[cfg_attr(feature = "speedy", derive(Readable, Writable))]
pub struct RelayUrl(pub String);

impl fmt::Display for RelayUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl RelayUrl {
    /// Create a new RelayUrl from a Url
    pub fn try_from_url(u: &Url) -> Result<RelayUrl, Error> {
        let url = url::Url::parse(&u.0)?;

        // Verify the scheme is websockets
        if url.scheme() != "wss" && url.scheme() != "ws" {
            return Err(Error::InvalidUrlScheme(url.scheme().to_owned()));
        }

        Ok(RelayUrl(url.as_str().to_owned()))
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

    #[test]
    fn test_url_case() {
        let url = Url::try_from_str("Wss://MyRelay.example.COM/PATH?Query").unwrap();
        assert_eq!(url.as_str(), "wss://myrelay.example.com/PATH?Query");
    }

    #[test]
    fn test_relay_url_slash() {
        let input = "Wss://MyRelay.example.COM";
        let url = RelayUrl::try_from_str(input).unwrap();
        assert_eq!(url.as_str(), "wss://myrelay.example.com/");
    }
}
