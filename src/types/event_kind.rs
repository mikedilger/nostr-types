use serde::de::Error as DeError;
use serde::de::{Deserialize, Deserializer, Visitor};
use serde::ser::{Serialize, Serializer};
use std::convert::From;
use std::fmt;

/// A kind of Event
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u64)]
pub enum EventKind {
    /// Event sets the metadata associated with a public key
    Metadata,
    /// Event is a text note
    TextNote,
    /// Event contains a relay URL which the author recommends
    RecommendRelay,
    /// Event contains tags which represent the authors contacts including the
    /// authors pet names for them
    ContactList,
    /// Event is an encrypted direct message
    EncryptedDirectMessage,
    /// Event is an authors request to delete previous events
    EventDeletion,
    /// Repost
    Repost,
    /// Event is a reaction to a `TextNote` event
    Reaction,
    /// Event creates a public channel
    ChannelCreation,
    /// Event sets metadata on a public channel
    ChannelMetadata,
    /// Event creates a message on a public channel
    ChannelMessage,
    /// Event hides a message on a public channel
    ChannelHideMessage,
    /// Event mutes a user on a public channel
    ChannelMuteUser,
    /// Reserved for future public channel usage
    PublicChatReserved45,
    /// Reserved for future public channel usage
    PublicChatReserved46,
    /// Reserved for future public channel usage
    PublicChatReserved47,
    /// Reserved for future public channel usage
    PublicChatReserved48,
    /// Reserved for future public channel usage
    PublicChatReserved49,
    /// Zap Request
    ZapRequest,
    /// Zap
    Zap,
    /// Relays List (NIP-23)
    RelaysListNip23,
    /// Relays List (NIP-65)
    RelayList,
    /// Authentication
    Auth,
    /// Long-form Content
    LongFormContent,
    /// Client Settings
    ClientSettings,
    /// Relay-specific replaceable event
    Replaceable(u64),
    /// Ephemeral event, sent to all clients with matching filters and should not be stored
    Ephemeral(u64),
    /// Something else?
    Other(u64),
}

impl EventKind {
    // Mock data for testing
    #[allow(dead_code)]
    pub(crate) fn mock() -> EventKind {
        EventKind::TextNote
    }

    /// If this event kind is a replaceable event
    /// NOTE: this does NOT count parameterized replaceable events
    pub fn is_replaceable(&self) -> bool {
        match *self {
            EventKind::Metadata => true,
            EventKind::ContactList => true,
            _ => {
                let u: u64 = From::from(*self);
                (10000..=19999).contains(&u)
            }
        }
    }

    /// If this event kind is ephemeral
    pub fn is_ephemeral(&self) -> bool {
        let u: u64 = From::from(*self);
        (20000..=29999).contains(&u)
    }

    /// If this event kind is parameterized replaceable
    pub fn is_parameterized_replaceable(&self) -> bool {
        let u: u64 = From::from(*self);
        (30000..=39999).contains(&u)
    }
}

impl From<u64> for EventKind {
    fn from(u: u64) -> Self {
        use EventKind::*;
        match u {
            0 => Metadata,
            1 => TextNote,
            2 => RecommendRelay,
            3 => ContactList,
            4 => EncryptedDirectMessage,
            5 => EventDeletion,
            6 => Repost,
            7 => Reaction,
            40 => ChannelCreation,
            41 => ChannelMetadata,
            42 => ChannelMessage,
            43 => ChannelHideMessage,
            44 => ChannelMuteUser,
            45 => PublicChatReserved45,
            46 => PublicChatReserved46,
            47 => PublicChatReserved47,
            48 => PublicChatReserved48,
            49 => PublicChatReserved49,
            9734 => ZapRequest,
            9735 => Zap,
            10001 => RelaysListNip23,
            10002 => RelayList,
            22242 => Auth,
            30023 => LongFormContent,
            31111 => ClientSettings,
            x if (10_000..20_000).contains(&x) => Replaceable(x),
            x if (20_000..30_000).contains(&x) => Ephemeral(x),
            x => Other(x),
        }
    }
}

impl From<EventKind> for u64 {
    fn from(e: EventKind) -> u64 {
        use EventKind::*;
        match e {
            Metadata => 0,
            TextNote => 1,
            RecommendRelay => 2,
            ContactList => 3,
            EncryptedDirectMessage => 4,
            EventDeletion => 5,
            Repost => 6,
            Reaction => 7,
            ChannelCreation => 40,
            ChannelMetadata => 41,
            ChannelMessage => 42,
            ChannelHideMessage => 43,
            ChannelMuteUser => 44,
            PublicChatReserved45 => 45,
            PublicChatReserved46 => 46,
            PublicChatReserved47 => 47,
            PublicChatReserved48 => 48,
            PublicChatReserved49 => 49,
            ZapRequest => 9734,
            Zap => 9735,
            RelaysListNip23 => 10001,
            RelayList => 10002,
            Auth => 22242,
            LongFormContent => 30023,
            ClientSettings => 31111,
            Replaceable(u) => u,
            Ephemeral(u) => u,
            Other(u) => u,
        }
    }
}

impl Serialize for EventKind {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let u: u64 = From::from(*self);
        serializer.serialize_u64(u)
    }
}

impl<'de> Deserialize<'de> for EventKind {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_u64(EventKindVisitor)
    }
}

struct EventKindVisitor;

impl Visitor<'_> for EventKindVisitor {
    type Value = EventKind;

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "an unsigned number that matches a known EventKind")
    }

    fn visit_u64<E>(self, v: u64) -> Result<EventKind, E>
    where
        E: DeError,
    {
        Ok(From::<u64>::from(v))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    test_serde! {EventKind, test_event_kind_serde}

    #[test]
    fn test_replaceable_ephemeral() {
        assert_eq!(EventKind::Metadata.is_replaceable(), true);
        assert_eq!(EventKind::TextNote.is_replaceable(), false);
        assert_eq!(EventKind::Zap.is_replaceable(), false);
        assert_eq!(EventKind::LongFormContent.is_replaceable(), false);

        assert_eq!(EventKind::TextNote.is_ephemeral(), false);
        assert_eq!(EventKind::Auth.is_ephemeral(), true);

        assert_eq!(EventKind::TextNote.is_parameterized_replaceable(), false);
        assert_eq!(
            EventKind::LongFormContent.is_parameterized_replaceable(),
            true
        );
    }
}
