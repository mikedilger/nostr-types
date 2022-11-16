use serde::de::Error as DeError;
use serde::de::{Deserialize, Deserializer, SeqAccess, Visitor};
use serde::ser::{Serialize, SerializeSeq, Serializer};
use std::fmt;

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

impl Tag {
    // Mock data for testing
    #[allow(dead_code)]
    pub(crate) fn mock() -> Tag {
        Tag::Event(vec!["p".to_owned(), "blah".to_owned(), "blah".to_owned()])
    }
}

impl Serialize for Tag {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Tag::Event(vec) => {
                let mut seq = serializer.serialize_seq(Some(1 + vec.len()))?;
                seq.serialize_element("e")?;
                for s in vec.iter() {
                    seq.serialize_element(s)?;
                }
                seq.end()
            }
            Tag::Pubkey(vec) => {
                let mut seq = serializer.serialize_seq(Some(1 + vec.len()))?;
                seq.serialize_element("p")?;
                for s in vec.iter() {
                    seq.serialize_element(s)?;
                }
                seq.end()
            }
        }
    }
}

impl<'de> Deserialize<'de> for Tag {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_seq(TagVisitor)
    }
}

struct TagVisitor;

impl<'de> Visitor<'de> for TagVisitor {
    type Value = Tag;

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "a sequence of strings")
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Tag, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let letter: &str = seq
            .next_element()?
            .ok_or_else(|| DeError::custom("Tag missing initial letter field"))?;
        if letter == "e" {
            let mut v: Vec<String> = Vec::new();
            loop {
                match seq.next_element()? {
                    None => return Ok(Tag::Event(v)),
                    Some(s) => v.push(s),
                }
            }
        } else if letter == "p" {
            let mut v: Vec<String> = Vec::new();
            loop {
                match seq.next_element()? {
                    None => return Ok(Tag::Pubkey(v)),
                    Some(s) => v.push(s),
                }
            }
        } else {
            Err(DeError::custom(format!("Unknown Tag: {}", letter)))
        }
    }
}
