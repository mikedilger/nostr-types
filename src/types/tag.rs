use crate::{Id, PublicKey, Url};
use serde::de::{Deserialize, Deserializer, SeqAccess, Visitor};
use serde::ser::{Serialize, SerializeSeq, Serializer};
use std::fmt;

/// A tag on an Event
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Tag {
    /// This is a reference to an event, where the first string is the event Id.
    /// The second string is defined in NIP-01 as an optional URL, but subsequent
    /// NIPs define more data and interpretations.
    Event {
        /// The Id of some other event that this event refers to
        id: Id,

        /// A recommended relay URL to find that other event
        recommended_relay_url: Option<Url>,

        /// A marker (commonly things like 'reply')
        marker: Option<String>,
    },

    /// This is a reference to a user by public key, where the first string is
    /// the PublicKey. The second string is defined in NIP-01 as an optional URL,
    /// but subsqeuent NIPs define more data and interpretations.
    Pubkey {
        /// The public key of the identity that this event refers to
        pubkey: PublicKey,

        /// A recommended relay URL to find information on that public key
        recommended_relay_url: Option<Url>,

        /// A petname given to this identity by the event author
        petname: Option<String>,
    },

    /// A hashtag
    Hashtag(String),

    /// A reference to a URL
    Reference(Url),

    /// A geohash
    Geohash(String),

    /// A subject. The first string is the subject. Should only be in TextNote events.
    Subject(String),

    /// A nonce tag for Proof of Work
    Nonce {
        /// A random number that makes the event hash meet the proof of work required
        nonce: String,

        /// The target number of bits for the proof of work
        target: Option<String>,
    },

    /// Any other tag
    Other {
        /// The tag name
        tag: String,

        /// The subsequent fields
        data: Vec<String>
    },

    /// An empty array (kept so signature remains valid across ser/de)
    Empty
}

impl Tag {
    /// Get the tag name for the tag (the first string in the array)a
    pub fn tagname(&self) -> String {
        match self {
            Tag::Event { .. } => "e".to_string(),
            Tag::Pubkey { .. } => "p".to_string(),
            Tag::Hashtag(_) => "t".to_string(),
            Tag::Reference(_) => "r".to_string(),
            Tag::Geohash(_) => "g".to_string(),
            Tag::Subject(_) => "subject".to_string(),
            Tag::Nonce { .. } => "nonce".to_string(),
            Tag::Other { tag, .. } => tag.clone(),
            Tag::Empty => panic!("empty tags have no tagname")
        }
    }

    // Mock data for testing
    #[allow(dead_code)]
    pub(crate) fn mock() -> Tag {
        Tag::Event {
            id: Id::mock(),
            recommended_relay_url: Some(Url::mock()),
            marker: None
        }
    }
}

impl Serialize for Tag {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Tag::Event { id, recommended_relay_url, marker } => {
                let mut seq = serializer.serialize_seq(None)?;
                seq.serialize_element("e")?;
                seq.serialize_element(id)?;
                if let Some(rru) = recommended_relay_url {
                    seq.serialize_element(rru)?;
                } else if marker.is_some() {
                    seq.serialize_element("")?;
                }
                if let Some(m) = marker {
                    seq.serialize_element(m)?;
                }
                seq.end()
            },
            Tag::Pubkey { pubkey, recommended_relay_url, petname } => {
                let mut seq = serializer.serialize_seq(None)?;
                seq.serialize_element("p")?;
                seq.serialize_element(pubkey)?;
                if let Some(rru) = recommended_relay_url {
                    seq.serialize_element(rru)?;
                } else if petname.is_some() {
                    seq.serialize_element("")?;
                }
                if let Some(pn) = petname {
                    seq.serialize_element(pn)?;
                }
                seq.end()
            },
            Tag::Hashtag(hashtag) => {
                let mut seq = serializer.serialize_seq(None)?;
                seq.serialize_element("t")?;
                seq.serialize_element(hashtag)?;
                seq.end()
            },
            Tag::Reference(reference) => {
                let mut seq = serializer.serialize_seq(None)?;
                seq.serialize_element("r")?;
                seq.serialize_element(reference)?;
                seq.end()
            },
            Tag::Geohash(geohash) => {
                let mut seq = serializer.serialize_seq(None)?;
                seq.serialize_element("g")?;
                seq.serialize_element(geohash)?;
                seq.end()
            },
            Tag::Subject(subject) => {
                let mut seq = serializer.serialize_seq(None)?;
                seq.serialize_element("subject")?;
                seq.serialize_element(subject)?;
                seq.end()
            },
            Tag::Nonce { nonce, target } => {
                let mut seq = serializer.serialize_seq(None)?;
                seq.serialize_element("nonce")?;
                seq.serialize_element(nonce)?;
                if let Some(t) = target {
                    seq.serialize_element(t)?;
                }
                seq.end()
            },
            Tag::Other { tag, data } => {
                let mut seq = serializer.serialize_seq(None)?;
                seq.serialize_element(tag)?;
                for s in data.iter() {
                    seq.serialize_element(s)?;
                }
                seq.end()
            },
            Tag::Empty => {
                let seq = serializer.serialize_seq(Some(0))?;
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
        let tagname: &str = match seq.next_element()? {
            Some(e) => e,
            None => return Ok(Tag::Empty),
        };
        if tagname == "e" {
            let id: Id = match seq.next_element()? {
                Some(id) => id,
                None => {
                    return Ok(Tag::Other { tag: tagname.to_string(), data: vec![] });
                }
            };
            let recommended_relay_url: Option<Url> = seq.next_element()?;
            let marker: Option<String> = seq.next_element()?;
            Ok(Tag::Event { id, recommended_relay_url, marker })
        } else if tagname == "p" {
            let pubkey: PublicKey = match seq.next_element()? {
                Some(p) => p,
                None => {
                    return Ok(Tag::Other { tag: tagname.to_string(), data: vec![] });
                }
            };
            let recommended_relay_url: Option<Url> = seq.next_element()?;
            let petname: Option<String> = seq.next_element()?;
            Ok(Tag::Pubkey { pubkey, recommended_relay_url, petname })
        } else if tagname == "t" {
            let tag = match seq.next_element()? {
                Some(t) => t,
                None => {
                    return Ok(Tag::Other { tag: tagname.to_string(), data: vec![] });
                }
            };
            Ok(Tag::Hashtag(tag))
        } else if tagname == "r" {
            let refr = match seq.next_element()? {
                Some(r) => r,
                None => {
                    return Ok(Tag::Other { tag: tagname.to_string(), data: vec![] });
                }
            };
            Ok(Tag::Reference(refr))
        } else if tagname == "g" {
            let geo = match seq.next_element()? {
                Some(g) => g,
                None => {
                    return Ok(Tag::Other { tag: tagname.to_string(), data: vec![] });
                }
            };
            Ok(Tag::Geohash(geo))
        } else if tagname == "subject" {
            let sub = match seq.next_element()? {
                Some(s) => s,
                None => {
                    return Ok(Tag::Other { tag: tagname.to_string(), data: vec![] });
                }
            };
            Ok(Tag::Subject(sub))
        } else if tagname == "nonce" {
            let nonce = match seq.next_element()? {
                Some(n) => n,
                None => {
                    return Ok(Tag::Other { tag: tagname.to_string(), data: vec![] });
                }
            };
            let target: Option<String> = seq.next_element()?;
            Ok(Tag::Nonce { nonce, target })
        } else {
            let mut data = Vec::new();
            loop {
                match seq.next_element()? {
                    None => return Ok(Tag::Other { tag: tagname.to_string(), data }),
                    Some(s) => data.push(s),
                }
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    test_serde! {Tag, test_tag_serde}
}
