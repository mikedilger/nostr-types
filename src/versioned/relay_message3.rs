use super::EventV2;
use crate::types::{Id, SubscriptionId};
use serde::de::Error as DeError;
use serde::de::{Deserialize, Deserializer, IgnoredAny, SeqAccess, Visitor};
use serde::ser::{Serialize, SerializeSeq, Serializer};
#[cfg(feature = "speedy")]
use speedy::{Readable, Writable};
use std::fmt;

/// A message from a relay to a client
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "speedy", derive(Readable, Writable))]
pub enum RelayMessageV3 {
    /// Used to send authentication challenges
    Auth(String),

    /// Used to indicate that a subscription was ended on the server side
    /// Every ClientMessage::Req _may_ trigger a RelayMessage::Closed response
    /// The last parameter may have a colon-terminated machine-readable prefix of:
    ///     duplicate, pow, blocked, rate-limited, invalid, auth-required,
    ///     restricted, or error
    Closed(SubscriptionId, String),

    /// End of subscribed events notification
    Eose(SubscriptionId),

    /// An event matching a subscription
    Event(SubscriptionId, Box<EventV2>),

    /// A human readable notice for errors and other information
    Notice(String),

    /// Used to notify clients if an event was successuful
    /// Every ClientMessage::Event will trigger a RelayMessage::OK response
    /// The last parameter may have a colon-terminated machine-readable prefix of:
    ///     duplicate, pow, blocked, rate-limited, invalid, auth-required,
    ///     restricted or error
    Ok(Id, bool, String),
}

/// The reason why a relay issued an OK or CLOSED message
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum Why {
    /// Authentication is required
    AuthRequired,

    /// You have been blocked from this relay
    Blocked,

    /// Your request is a duplicate
    Duplicate,

    /// Other error
    Error,

    /// Your request is invalid
    Invalid,

    /// Proof-of-work is required
    Pow,

    /// Rejected due to rate limiting
    RateLimited,

    /// The action you requested is restricted to your identity
    Restricted,
}

impl RelayMessageV3 {
    /// Translate the machine-readable prefix from the message
    pub fn why(&self) -> Option<Why> {
        let s = match *self {
            RelayMessageV3::Closed(_, ref s) => s,
            RelayMessageV3::Ok(_, _, ref s) => s,
            _ => return None,
        };

        match s.split(':').next() {
            Some("auth-required") => Some(Why::AuthRequired),
            Some("blocked") => Some(Why::Blocked),
            Some("duplicate") => Some(Why::Duplicate),
            Some("error") => Some(Why::Error),
            Some("invalid") => Some(Why::Invalid),
            Some("pow") => Some(Why::Pow),
            Some("rate-limited") => Some(Why::RateLimited),
            Some("restricted") => Some(Why::Restricted),
            _ => None,
        }
    }

    // Mock data for testing
    #[allow(dead_code)]
    pub(crate) fn mock() -> RelayMessageV3 {
        RelayMessageV3::Event(SubscriptionId::mock(), Box::new(EventV2::mock()))
    }
}

impl Serialize for RelayMessageV3 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            RelayMessageV3::Auth(challenge) => {
                let mut seq = serializer.serialize_seq(Some(2))?;
                seq.serialize_element("AUTH")?;
                seq.serialize_element(&challenge)?;
                seq.end()
            }
            RelayMessageV3::Closed(id, message) => {
                let mut seq = serializer.serialize_seq(Some(3))?;
                seq.serialize_element("CLOSED")?;
                seq.serialize_element(&id)?;
                seq.serialize_element(&message)?;
                seq.end()
            }
            RelayMessageV3::Eose(id) => {
                let mut seq = serializer.serialize_seq(Some(2))?;
                seq.serialize_element("EOSE")?;
                seq.serialize_element(&id)?;
                seq.end()
            }
            RelayMessageV3::Event(id, event) => {
                let mut seq = serializer.serialize_seq(Some(3))?;
                seq.serialize_element("EVENT")?;
                seq.serialize_element(&id)?;
                seq.serialize_element(&event)?;
                seq.end()
            }
            RelayMessageV3::Notice(s) => {
                let mut seq = serializer.serialize_seq(Some(2))?;
                seq.serialize_element("NOTICE")?;
                seq.serialize_element(&s)?;
                seq.end()
            }
            RelayMessageV3::Ok(id, ok, message) => {
                let mut seq = serializer.serialize_seq(Some(4))?;
                seq.serialize_element("OK")?;
                seq.serialize_element(&id)?;
                seq.serialize_element(&ok)?;
                seq.serialize_element(&message)?;
                seq.end()
            }
        }
    }
}

impl<'de> Deserialize<'de> for RelayMessageV3 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_seq(RelayMessageVisitor)
    }
}

struct RelayMessageVisitor;

impl<'de> Visitor<'de> for RelayMessageVisitor {
    type Value = RelayMessageV3;

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "a sequence of strings")
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<RelayMessageV3, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let word: &str = seq
            .next_element()?
            .ok_or_else(|| DeError::custom("Message missing initial string field"))?;
        let mut output: Option<RelayMessageV3> = None;
        if word == "EVENT" {
            let id: SubscriptionId = seq
                .next_element()?
                .ok_or_else(|| DeError::custom("Message missing id field"))?;
            let event: EventV2 = seq
                .next_element()?
                .ok_or_else(|| DeError::custom("Message missing event field"))?;
            output = Some(RelayMessageV3::Event(id, Box::new(event)));
        } else if word == "NOTICE" {
            let s: String = seq
                .next_element()?
                .ok_or_else(|| DeError::custom("Message missing string field"))?;
            output = Some(RelayMessageV3::Notice(s));
        } else if word == "EOSE" {
            let id: SubscriptionId = seq
                .next_element()?
                .ok_or_else(|| DeError::custom("Message missing id field"))?;
            output = Some(RelayMessageV3::Eose(id))
        } else if word == "OK" {
            let id: Id = seq
                .next_element()?
                .ok_or_else(|| DeError::custom("Message missing id field"))?;
            let ok: bool = seq
                .next_element()?
                .ok_or_else(|| DeError::custom("Message missing ok field"))?;
            let message: String = seq
                .next_element()?
                .ok_or_else(|| DeError::custom("Message missing string field"))?;
            output = Some(RelayMessageV3::Ok(id, ok, message));
        } else if word == "AUTH" {
            let challenge: String = seq
                .next_element()?
                .ok_or_else(|| DeError::custom("Message missing challenge field"))?;
            output = Some(RelayMessageV3::Auth(challenge));
        } else if word == "CLOSED" {
            let id: SubscriptionId = seq
                .next_element()?
                .ok_or_else(|| DeError::custom("Message messing id field"))?;
            let message: String = seq
                .next_element()?
                .ok_or_else(|| DeError::custom("Message missing string field"))?;
            output = Some(RelayMessageV3::Closed(id, message));
        }

        // Consume any trailing fields
        while let Some(_ignored) = seq.next_element::<IgnoredAny>()? {}

        match output {
            Some(rm) => Ok(rm),
            None => Err(DeError::custom(format!("Unknown Message: {word}"))),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    test_serde! {RelayMessageV3, test_relay_message_serde}
}
