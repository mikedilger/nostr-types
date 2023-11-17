use super::EventV1;
use crate::types::{Filter, SubscriptionId};
use serde::de::Error as DeError;
use serde::de::{Deserialize, Deserializer, IgnoredAny, SeqAccess, Visitor};
use serde::ser::{Serialize, SerializeSeq, Serializer};
#[cfg(feature = "speedy")]
use speedy::{Readable, Writable};
use std::fmt;

/// A message from a client to a relay
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "speedy", derive(Readable, Writable))]
pub enum ClientMessageV1 {
    /// An event
    Event(Box<EventV1>),

    /// A subscription request
    Req(SubscriptionId, Vec<Filter>),

    /// A request to close a subscription
    Close(SubscriptionId),

    /// Used to send authentication events
    Auth(Box<EventV1>),
}

impl ClientMessageV1 {
    // Mock data for testing
    #[allow(dead_code)]
    pub(crate) fn mock() -> ClientMessageV1 {
        ClientMessageV1::Event(Box::new(EventV1::mock()))
    }
}

impl Serialize for ClientMessageV1 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            ClientMessageV1::Event(event) => {
                let mut seq = serializer.serialize_seq(Some(2))?;
                seq.serialize_element("EVENT")?;
                seq.serialize_element(&event)?;
                seq.end()
            }
            ClientMessageV1::Req(id, filters) => {
                let mut seq = serializer.serialize_seq(Some(3))?;
                seq.serialize_element("REQ")?;
                seq.serialize_element(&id)?;
                for filter in filters {
                    seq.serialize_element(&filter)?;
                }
                seq.end()
            }
            ClientMessageV1::Close(id) => {
                let mut seq = serializer.serialize_seq(Some(2))?;
                seq.serialize_element("CLOSE")?;
                seq.serialize_element(&id)?;
                seq.end()
            }
            ClientMessageV1::Auth(event) => {
                let mut seq = serializer.serialize_seq(Some(2))?;
                seq.serialize_element("AUTH")?;
                seq.serialize_element(&event)?;
                seq.end()
            }
        }
    }
}

impl<'de> Deserialize<'de> for ClientMessageV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_seq(ClientMessageVisitor)
    }
}

struct ClientMessageVisitor;

impl<'de> Visitor<'de> for ClientMessageVisitor {
    type Value = ClientMessageV1;

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "a sequence of strings")
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<ClientMessageV1, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let word: &str = seq
            .next_element()?
            .ok_or_else(|| DeError::custom("Message missing initial string field"))?;
        let mut output: Option<ClientMessageV1> = None;
        if word == "EVENT" {
            let event: EventV1 = seq
                .next_element()?
                .ok_or_else(|| DeError::custom("Message missing event field"))?;
            output = Some(ClientMessageV1::Event(Box::new(event)))
        } else if word == "REQ" {
            let id: SubscriptionId = seq
                .next_element()?
                .ok_or_else(|| DeError::custom("Message missing id field"))?;
            let mut filters: Vec<Filter> = vec![];
            loop {
                let f: Option<Filter> = seq.next_element()?;
                match f {
                    None => break,
                    Some(fil) => filters.push(fil),
                }
            }
            output = Some(ClientMessageV1::Req(id, filters))
        } else if word == "CLOSE" {
            let id: SubscriptionId = seq
                .next_element()?
                .ok_or_else(|| DeError::custom("Message missing id field"))?;
            output = Some(ClientMessageV1::Close(id))
        } else if word == "AUTH" {
            let event: EventV1 = seq
                .next_element()?
                .ok_or_else(|| DeError::custom("Message missing event field"))?;
            output = Some(ClientMessageV1::Auth(Box::new(event)))
        }

        // Consume any trailing fields
        while let Some(_ignored) = seq.next_element::<IgnoredAny>()? {}

        match output {
            Some(cm) => Ok(cm),
            None => Err(DeError::custom(format!("Unknown Message: {word}"))),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    test_serde! {ClientMessageV1, test_client_message_serde}
}
