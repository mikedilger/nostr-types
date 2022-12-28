use super::PublicKeyHex;
use serde::{Deserialize, Serialize};
use std::fmt;

/// Relay information document as described in NIP-11, supplied by a relay
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RelayInformationDocument {
    /// Name of the relay
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// Description of the relay in plain text
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Public key of an administrative contact of the relay
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pubkey: Option<PublicKeyHex>,

    /// An administrative contact for the relay. Should be a URI.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contact: Option<String>,

    /// A list of NIPs supported by the relay
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub supported_nips: Vec<u32>,

    /// The software running the relay
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub software: Option<String>,

    /// The software version
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

impl RelayInformationDocument {
    /// If the relay supports the queried `nip`
    pub fn supports_nip(&self, nip: u32) -> bool {
        self.supported_nips.contains(&nip)
    }
}

impl fmt::Display for RelayInformationDocument {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Relay Information:")?;
        if let Some(name) = &self.name {
            write!(f, " Name=\"{}\"", name)?;
        }
        if let Some(desc) = &self.description {
            write!(f, " Description=\"{}\"", desc)?;
        }
        if let Some(contact) = &self.contact {
            write!(f, " Contact=\"{}\"", contact)?;
        }
        if let Some(pubkey) = &self.pubkey {
            write!(f, " Pubkey=\"{}\"", pubkey)?;
        }
        if let Some(software) = &self.software {
            write!(f, " Software=\"{}\"", software)?;
        }
        if let Some(version) = &self.version {
            write!(f, " Version=\"{}\"", version)?;
        }
        write!(f, " NIPS={:?}", self.supported_nips)?;
        Ok(())
    }
}
