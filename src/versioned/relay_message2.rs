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
pub enum RelayMessageV2 {
    /// An event matching a subscription
    Event(SubscriptionId, Box<EventV2>),

    /// A human readable notice for errors and other information
    Notice(String),

    /// End of subscribed events notification
    Eose(SubscriptionId),

    /// Used to notify clients if an event was successuful
    Ok(Id, bool, String),

    /// Used to send authentication challenges
    Auth(String),
}

impl RelayMessageV2 {
    // Mock data for testing
    #[allow(dead_code)]
    pub(crate) fn mock() -> RelayMessageV2 {
        RelayMessageV2::Event(SubscriptionId::mock(), Box::new(EventV2::mock()))
    }
}

impl Serialize for RelayMessageV2 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            RelayMessageV2::Event(id, event) => {
                let mut seq = serializer.serialize_seq(Some(3))?;
                seq.serialize_element("EVENT")?;
                seq.serialize_element(&id)?;
                seq.serialize_element(&event)?;
                seq.end()
            }
            RelayMessageV2::Notice(s) => {
                let mut seq = serializer.serialize_seq(Some(2))?;
                seq.serialize_element("NOTICE")?;
                seq.serialize_element(&s)?;
                seq.end()
            }
            RelayMessageV2::Eose(id) => {
                let mut seq = serializer.serialize_seq(Some(2))?;
                seq.serialize_element("EOSE")?;
                seq.serialize_element(&id)?;
                seq.end()
            }
            RelayMessageV2::Ok(id, ok, message) => {
                let mut seq = serializer.serialize_seq(Some(4))?;
                seq.serialize_element("OK")?;
                seq.serialize_element(&id)?;
                seq.serialize_element(&ok)?;
                seq.serialize_element(&message)?;
                seq.end()
            }
            RelayMessageV2::Auth(challenge) => {
                let mut seq = serializer.serialize_seq(Some(2))?;
                seq.serialize_element("AUTH")?;
                seq.serialize_element(&challenge)?;
                seq.end()
            }
        }
    }
}

impl<'de> Deserialize<'de> for RelayMessageV2 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_seq(RelayMessageVisitor)
    }
}

struct RelayMessageVisitor;

impl<'de> Visitor<'de> for RelayMessageVisitor {
    type Value = RelayMessageV2;

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "a sequence of strings")
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<RelayMessageV2, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let word: &str = seq
            .next_element()?
            .ok_or_else(|| DeError::custom("Message missing initial string field"))?;
        let mut output: Option<RelayMessageV2> = None;
        if word == "EVENT" {
            let id: SubscriptionId = seq
                .next_element()?
                .ok_or_else(|| DeError::custom("Message missing id field"))?;
            let event: EventV2 = seq
                .next_element()?
                .ok_or_else(|| DeError::custom("Message missing event field"))?;
            output = Some(RelayMessageV2::Event(id, Box::new(event)));
        } else if word == "NOTICE" {
            let s: String = seq
                .next_element()?
                .ok_or_else(|| DeError::custom("Message missing string field"))?;
            output = Some(RelayMessageV2::Notice(s));
        } else if word == "EOSE" {
            let id: SubscriptionId = seq
                .next_element()?
                .ok_or_else(|| DeError::custom("Message missing id field"))?;
            output = Some(RelayMessageV2::Eose(id))
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
            output = Some(RelayMessageV2::Ok(id, ok, message));
        } else if word == "AUTH" {
            let challenge: String = seq
                .next_element()?
                .ok_or_else(|| DeError::custom("Message missing challenge field"))?;
            output = Some(RelayMessageV2::Auth(challenge));
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

    test_serde! {RelayMessageV2, test_relay_message_serde}
}
