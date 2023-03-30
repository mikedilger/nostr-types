use super::{EventPointer, Id, Profile, PublicKey};
//use lazy_static::lazy_static;

/// A bech32 sequence representing a nostr object (or set of objects)
// note, internally we store them as the object the sequence represents
#[derive(Debug)]
pub enum NostrBech32 {
    /// npub - a NostrUrl representing a public key
    Pubkey(PublicKey),
    /// nprofile - a NostrUrl representing a public key and a set of relay URLs
    Profile(Profile),
    /// note - a NostrUrl representing an event
    Id(Id),
    /// nevent - a NostrUrl representing an event and a set of relay URLs
    EventPointer(EventPointer),
}

impl std::fmt::Display for NostrBech32 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        match &*self {
            NostrBech32::Pubkey(pk) => write!(f, "{}", pk.as_bech32_string()),
            NostrBech32::Profile(p) => write!(f, "{}", p.as_bech32_string()),
            NostrBech32::Id(i) => write!(f, "{}", i.as_bech32_string()),
            NostrBech32::EventPointer(ep) => write!(f, "{}", ep.as_bech32_string()),
        }
    }
}

/// A nostr url, representing a NostrBech32 but with a 'nostr:' prefix
#[derive(Debug)]
pub struct NostrUrl(NostrBech32);

impl std::fmt::Display for NostrUrl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(f, "nostr:")?;
        self.0.fmt(f)
    }
}
