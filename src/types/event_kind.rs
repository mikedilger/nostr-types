use serde::de::Error as DeError;
use serde::de::{Deserializer, Visitor};
use serde::ser::Serializer;
use serde::{Deserialize, Serialize};
#[cfg(feature = "speedy")]
use speedy::{Context, Readable, Reader, Writable, Writer};
use std::convert::From;
use std::fmt;

/// A kind of Event
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum EventKind {
    /// Event sets the metadata associated with a public key
    Metadata = 0,
    /// Event is a text note
    TextNote = 1,
    /// Event contains a relay URL which the author recommends
    RecommendRelay = 2,
    /// Event contains tags which represent the authors contacts including the
    /// authors pet names for them
    ContactList = 3,
    /// Event is an encrypted direct message
    EncryptedDirectMessage = 4,
    /// Event is an authors request to delete previous events
    EventDeletion = 5,
    /// Repost
    Repost = 6,
    /// Event is a reaction to a `TextNote` event
    Reaction = 7,
    /// Event creates a public channel
    ChannelCreation = 40,
    /// Event sets metadata on a public channel
    ChannelMetadata = 41,
    /// Event creates a message on a public channel
    ChannelMessage = 42,
    /// Event hides a message on a public channel
    ChannelHideMessage = 43,
    /// Event mutes a user on a public channel
    ChannelMuteUser = 44,
    /// Reserved for future public channel usage
    PublicChatReserved45 = 45,
    /// Reserved for future public channel usage
    PublicChatReserved46 = 46,
    /// Reserved for future public channel usage
    PublicChatReserved47 = 47,
    /// Reserved for future public channel usage
    PublicChatReserved48 = 48,
    /// Reserved for future public channel usage
    PublicChatReserved49 = 49,
    /// Zap Request
    ZapRequest = 9734,
    /// Zap
    Zap = 9735,
    /// Relays List (NIP-23)
    RelaysListNip23 = 10001,
    /// Relays List (NIP-65)
    RelayList = 10002,
    /// Authentication
    Auth = 22242,
    /// Long-form Content
    LongFormContent = 30023,
    /// Client Settings
    ClientSettings = 31111,
    /// Relay-specific replaceable event
    Replaceable(u32),
    /// Ephemeral event, sent to all clients with matching filters and should not be stored
    Ephemeral(u32),
    /// Something else?
    Other(u32),
}

use EventKind::*;

impl EventKind {
    // Mock data for testing
    #[allow(dead_code)]
    pub(crate) fn mock() -> EventKind {
        TextNote
    }

    /// If this event kind is a replaceable event
    /// NOTE: this does NOT count parameterized replaceable events
    pub fn is_replaceable(&self) -> bool {
        match *self {
            Metadata => true,
            ContactList => true,
            _ => {
                let u: u32 = From::from(*self);
                (10000..=19999).contains(&u)
            }
        }
    }

    /// If this event kind is ephemeral
    pub fn is_ephemeral(&self) -> bool {
        let u: u32 = From::from(*self);
        (20000..=29999).contains(&u)
    }

    /// If this event kind is parameterized replaceable
    pub fn is_parameterized_replaceable(&self) -> bool {
        let u: u32 = From::from(*self);
        (30000..=39999).contains(&u)
    }

    /// If this event kind is feed related.
    pub fn is_feed_related(&self) -> bool {
        self.is_feed_displayable() || self.augments_feed_related()
    }

    /// If this event kind is feed displayable.
    pub fn is_feed_displayable(&self) -> bool {
        matches!(
            *self,
            TextNote | EncryptedDirectMessage | Repost | LongFormContent
        )
    }

    /// If this event kind augments a feed related event
    pub fn augments_feed_related(&self) -> bool {
        matches!(*self, EventDeletion | Reaction | Zap)
    }

    /// This iterates through every well-known EventKind
    pub fn iter() -> EventKindIterator {
        EventKindIterator::new()
    }
}

/// Iterator over well known `EventKind`s
#[derive(Clone, Copy, Debug)]
pub struct EventKindIterator {
    pos: usize,
}

static WELL_KNOWN_KINDS: &[EventKind] = &[
    Metadata,
    TextNote,
    RecommendRelay,
    ContactList,
    EncryptedDirectMessage,
    EventDeletion,
    Repost,
    Reaction,
    ChannelCreation,
    ChannelMetadata,
    ChannelMessage,
    ChannelHideMessage,
    ChannelMuteUser,
    PublicChatReserved45,
    PublicChatReserved46,
    PublicChatReserved47,
    PublicChatReserved48,
    PublicChatReserved49,
    ZapRequest,
    Zap,
    RelaysListNip23,
    RelayList,
    Auth,
    LongFormContent,
    ClientSettings,
];

impl EventKindIterator {
    fn new() -> EventKindIterator {
        EventKindIterator { pos: 0 }
    }
}

impl Iterator for EventKindIterator {
    type Item = EventKind;

    fn next(&mut self) -> Option<EventKind> {
        if self.pos == WELL_KNOWN_KINDS.len() {
            None
        } else {
            let rval = WELL_KNOWN_KINDS[self.pos];
            self.pos += 1;
            Some(rval)
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.pos, Some(WELL_KNOWN_KINDS.len()))
    }
}

impl From<u32> for EventKind {
    fn from(u: u32) -> Self {
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

impl From<EventKind> for u32 {
    fn from(e: EventKind) -> u32 {
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
        let u: u32 = From::from(*self);
        serializer.serialize_u32(u)
    }
}

impl<'de> Deserialize<'de> for EventKind {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_u32(EventKindVisitor)
    }
}

struct EventKindVisitor;

impl Visitor<'_> for EventKindVisitor {
    type Value = EventKind;

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "an unsigned number that matches a known EventKind")
    }

    fn visit_u32<E>(self, v: u32) -> Result<EventKind, E>
    where
        E: DeError,
    {
        Ok(From::<u32>::from(v))
    }

    // JsonValue numbers come in as u64
    fn visit_u64<E>(self, v: u64) -> Result<EventKind, E>
    where
        E: DeError,
    {
        Ok(From::<u32>::from(v as u32))
    }
}

#[cfg(feature = "speedy")]
impl<'a, C: Context> Readable<'a, C> for EventKind {
    #[inline]
    fn read_from<R: Reader<'a, C>>(reader: &mut R) -> Result<Self, C::Error> {
        let value = u32::read_from(reader)?;
        Ok(value.into())
    }

    #[inline]
    fn minimum_bytes_needed() -> usize {
        <u32 as Readable<'a, C>>::minimum_bytes_needed()
    }
}

#[cfg(feature = "speedy")]
impl<C: Context> Writable<C> for EventKind {
    #[inline]
    fn write_to<T: ?Sized + Writer<C>>(&self, writer: &mut T) -> Result<(), C::Error> {
        writer.write_u32(u32::from(*self))
    }

    #[inline]
    fn bytes_needed(&self) -> Result<usize, C::Error> {
        Ok(std::mem::size_of::<u32>())
    }
}

/// Either an EventKind or a range (a vector of length 2 with start and end)
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "speedy", derive(Readable, Writable))]
#[serde(untagged)]
pub enum EventKindOrRange {
    /// A single EventKind
    EventKind(EventKind),

    /// A range of EventKinds
    // NOTE: the internal Vec should have exactly 2 fields.  To force this with a tuple
    //       struct makes ser/de a bitch, so we don't.
    Range(Vec<EventKind>),
}

#[cfg(test)]
mod test {
    use super::*;

    test_serde! {EventKind, test_event_kind_serde}

    #[test]
    fn test_replaceable_ephemeral() {
        assert!(Metadata.is_replaceable());
        assert!(!TextNote.is_replaceable());
        assert!(!Zap.is_replaceable());
        assert!(!LongFormContent.is_replaceable());

        assert!(!TextNote.is_ephemeral());
        assert!(Auth.is_ephemeral());

        assert!(!TextNote.is_parameterized_replaceable());
        assert!(LongFormContent.is_parameterized_replaceable());
    }

    #[cfg(feature = "speedy")]
    #[test]
    fn test_speedy_event_kind() {
        let ek = EventKind::mock();
        let bytes = ek.write_to_vec().unwrap();
        let ek2 = EventKind::read_from_buffer(&bytes).unwrap();
        assert_eq!(ek, ek2);
    }
}
