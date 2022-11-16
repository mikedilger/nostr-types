use crate::{Error, Id, PublicKey, Url};
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
    /// Get the ID field from an Event Tag
    pub fn get_id(&self) -> Result<Option<Id>, Error> {
        if let Tag::Event(v) = self {
            if let Some(st) = v.get(0) {
                return Ok(Some(serde_json::from_str(st)?));
            }
        }
        Ok(None)
    }

    /// Get the URL field from a Tag
    pub fn get_url(&self) -> Result<Option<Url>, Error> {
        if let Tag::Event(v) = self {
            if let Some(u) = v.get(1) {
                return Ok(Some(Url(u.to_owned())));
            }
        }
        if let Tag::Pubkey(v) = self {
            if let Some(u) = v.get(1) {
                return Ok(Some(Url(u.to_owned())));
            }
        }
        Ok(None)
    }

    /// Get the PublicKey from a Public Key Tag
    pub fn get_public_key(&self) -> Result<Option<PublicKey>, Error> {
        if let Tag::Pubkey(v) = self {
            if let Some(p) = v.get(0) {
                return Ok(Some(serde_json::from_str(p)?));
            }
        }
        Ok(None)
    }

    /// Get a String from a Tag at the position `n`
    pub fn get_string(&self, n: usize) -> Option<String> {
        if let Tag::Event(v) = self {
            if let Some(s) = v.get(n) {
                return Some(s.to_owned());
            }
        }
        if let Tag::Pubkey(v) = self {
            if let Some(s) = v.get(n) {
                return Some(s.to_owned());
            }
        }
        None
    }

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

#[cfg(test)]
mod test {
    use super::*;

    test_serde! {Tag, test_tag_serde}
}
