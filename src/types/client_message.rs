use super::{Event, Filters, SubscriptionId};
use serde::de::Error as DeError;
use serde::de::{Deserialize, Deserializer, SeqAccess, Visitor};
use serde::ser::{Serialize, SerializeSeq, Serializer};
use std::fmt;

/// A message from a client to a relay
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ClientMessage {
    /// An event
    Event(Box<Event>),

    /// A subscription request
    Req(SubscriptionId, Vec<Filters>),

    /// A request to close a subscription
    Close(SubscriptionId),
}

impl ClientMessage {
    // Mock data for testing
    #[allow(dead_code)]
    pub(crate) fn mock() -> ClientMessage {
        ClientMessage::Event(Box::new(Event::mock()))
    }
}

impl Serialize for ClientMessage {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            ClientMessage::Event(event) => {
                let mut seq = serializer.serialize_seq(Some(2))?;
                seq.serialize_element("EVENT")?;
                seq.serialize_element(&event)?;
                seq.end()
            }
            ClientMessage::Req(id, filters) => {
                let mut seq = serializer.serialize_seq(Some(3))?;
                seq.serialize_element("REQ")?;
                seq.serialize_element(&id)?;
                for filter in filters {
                    seq.serialize_element(&filter)?;
                }
                seq.end()
            }
            ClientMessage::Close(id) => {
                let mut seq = serializer.serialize_seq(Some(2))?;
                seq.serialize_element("CLOSE")?;
                seq.serialize_element(&id)?;
                seq.end()
            }
        }
    }
}

impl<'de> Deserialize<'de> for ClientMessage {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_seq(ClientMessageVisitor)
    }
}

struct ClientMessageVisitor;

impl<'de> Visitor<'de> for ClientMessageVisitor {
    type Value = ClientMessage;

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "a sequence of strings")
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<ClientMessage, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let word: &str = seq
            .next_element()?
            .ok_or_else(|| DeError::custom("Message missing initial string field"))?;
        if word == "EVENT" {
            let event: Event = seq
                .next_element()?
                .ok_or_else(|| DeError::custom("Message missing event field"))?;
            Ok(ClientMessage::Event(Box::new(event)))
        } else if word == "REQ" {
            let id: SubscriptionId = seq
                .next_element()?
                .ok_or_else(|| DeError::custom("Message missing id field"))?;
            let mut filters: Vec<Filters> = vec![];
            loop {
                let f: Option<Filters> = seq.next_element()?;
                match f {
                    None => break,
                    Some(fil) => filters.push(fil),
                }
            }
            Ok(ClientMessage::Req(id, filters))
        } else if word == "CLOSE" {
            let id: SubscriptionId = seq
                .next_element()?
                .ok_or_else(|| DeError::custom("Message missing id field"))?;
            Ok(ClientMessage::Close(id))
        } else {
            Err(DeError::custom(format!("Unknown Message: {}", word)))
        }
    }
}
