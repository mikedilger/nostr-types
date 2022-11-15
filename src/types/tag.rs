/// A tag on an Event
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Tag {
    /// This is a reference to an event, where the first string is the event Id.
    /// The second string is defined in NIP-01 as an optional URL, but subsequent
    /// NIPs define more data and interpretations.
    Event(Vec<String>),

    /// This is a reference to a user by public key, where the first string is
    /// the PublicKey. The second string is defined in NIP-01 as an optional URL,
    /// but subsqeuent NIPs define more data and interpretations.
    Pubkey(Vec<String>),
}
