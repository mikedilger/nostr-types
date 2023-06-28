use crate::{
    DelegationConditions, EventKind, Id, PublicKeyHex, SignatureHex, UncheckedUrl, Unixtime,
};
use serde::de::{Deserialize, Deserializer, SeqAccess, Visitor};
use serde::ser::{Serialize, SerializeSeq, Serializer};
#[cfg(feature = "speedy")]
use speedy::{Readable, Writable};
use std::fmt;

/// A tag on an Event
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "speedy", derive(Readable, Writable))]
pub enum Tag {
    /// Address 'a' tag to a parameterized replaceable event
    Address {
        /// EventKind
        kind: EventKind,

        /// Author
        pubkey: PublicKeyHex,

        /// d-tag identifier
        d: String,

        /// Relay URL
        relay_url: Option<UncheckedUrl>,

        /// Trailing
        trailing: Vec<String>,
    },

    /// Content Warning to alert client to hide content until user approves
    ContentWarning {
        /// Content warning
        warning: String,

        /// Trailing
        trailing: Vec<String>,
    },

    /// Delegation (Delegated Event Signing)
    Delegation {
        /// Public key of the delegator
        pubkey: PublicKeyHex,

        /// Conditions query string
        conditions: DelegationConditions,

        /// 64-byte schnorr signature of the sha256 hash of the delegation token
        sig: SignatureHex,

        /// Trailing
        trailing: Vec<String>,
    },

    /// This is a reference to an event, where the first string is the event Id.
    /// The second string is defined in NIP-01 as an optional URL, but subsequent
    /// 'e' NIPs define more data and interpretations.
    Event {
        /// The Id of some other event that this event refers to
        id: Id,

        /// A recommended relay URL to find that other event
        recommended_relay_url: Option<UncheckedUrl>,

        /// A marker (commonly things like 'reply')
        marker: Option<String>,

        /// Trailing
        trailing: Vec<String>,
    },

    /// A time when the event should be considered expired
    Expiration {
        /// Expiration Time
        time: Unixtime,

        /// Trailing
        trailing: Vec<String>,
    },

    /// 'p' This is a reference to a user by public key, where the first string is
    /// the PublicKey. The second string is defined in NIP-01 as an optional URL,
    /// but subsqeuent NIPs define more data and interpretations.
    Pubkey {
        /// The public key of the identity that this event refers to
        pubkey: PublicKeyHex,

        /// A recommended relay URL to find information on that public key
        recommended_relay_url: Option<UncheckedUrl>,

        /// A petname given to this identity by the event author
        petname: Option<String>,

        /// Trailing
        trailing: Vec<String>,
    },

    /// 't' A hashtag
    Hashtag {
        /// Hashtag
        hashtag: String,

        /// Trailing
        trailing: Vec<String>,
    },

    /// 'r' A reference to a URL
    Reference {
        /// A relay url
        url: UncheckedUrl,

        /// An optional marker
        marker: Option<String>,

        /// Trailing
        trailing: Vec<String>,
    },

    /// 'g' A geohash
    Geohash {
        /// A geohash
        geohash: String,

        /// Trailing
        trailing: Vec<String>,
    },

    /// 'd' Identifier tag
    Identifier {
        /// 'd' indentifier
        d: String,

        /// Trailing
        trailing: Vec<String>,
    },

    /// A subject. The first string is the subject. Should only be in TextNote events.
    Subject {
        /// The subject
        subject: String,

        /// Trailing
        trailing: Vec<String>,
    },

    /// A nonce tag for Proof of Work
    Nonce {
        /// A random number that makes the event hash meet the proof of work required
        nonce: String,

        /// The target number of bits for the proof of work
        target: Option<String>,

        /// Trailing
        trailing: Vec<String>,
    },

    /// Parameter of a parameterized replaceable event
    Parameter {
        /// Parameter
        param: String,

        /// Trailing
        trailing: Vec<String>,
    },

    /// Title (30023 long form)
    Title {
        /// Title
        title: String,

        /// Trailing
        trailing: Vec<String>,
    },

    /// Any other tag
    Other {
        /// The tag name
        tag: String,

        /// The subsequent fields
        data: Vec<String>,
    },

    /// An empty array (kept so signature remains valid across ser/de)
    Empty,
}

impl Tag {
    /// Get the tag name for the tag (the first string in the array)a
    pub fn tagname(&self) -> String {
        match self {
            Tag::Address { .. } => "address".to_string(),
            Tag::ContentWarning { .. } => "content-warning".to_string(),
            Tag::Delegation { .. } => "delegation".to_string(),
            Tag::Event { .. } => "e".to_string(),
            Tag::Expiration { .. } => "expiration".to_string(),
            Tag::Pubkey { .. } => "p".to_string(),
            Tag::Hashtag { .. } => "t".to_string(),
            Tag::Reference { .. } => "r".to_string(),
            Tag::Geohash { .. } => "g".to_string(),
            Tag::Identifier { .. } => "d".to_string(),
            Tag::Subject { .. } => "subject".to_string(),
            Tag::Nonce { .. } => "nonce".to_string(),
            Tag::Parameter { .. } => "parameter".to_string(),
            Tag::Title { .. } => "title".to_string(),
            Tag::Other { tag, .. } => tag.clone(),
            Tag::Empty => panic!("empty tags have no tagname"),
        }
    }

    // Mock data for testing
    #[allow(dead_code)]
    pub(crate) fn mock() -> Tag {
        Tag::Event {
            id: Id::mock(),
            recommended_relay_url: Some(UncheckedUrl::mock()),
            marker: None,
            trailing: Vec::new(),
        }
    }
}

impl Serialize for Tag {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Tag::Address {
                kind,
                pubkey,
                d,
                relay_url,
                trailing,
            } => {
                let mut seq = serializer.serialize_seq(None)?;
                seq.serialize_element("a")?;
                let k: u32 = From::from(*kind);
                let s = format!("{}:{}:{}", k, pubkey, d);
                seq.serialize_element(&s)?;
                if let Some(ru) = relay_url {
                    seq.serialize_element(ru)?;
                } else if !trailing.is_empty() {
                    seq.serialize_element("")?;
                }
                for s in trailing {
                    seq.serialize_element(s)?;
                }
                seq.end()
            }
            Tag::ContentWarning { warning, trailing } => {
                let mut seq = serializer.serialize_seq(None)?;
                seq.serialize_element("content-warning")?;
                seq.serialize_element(warning)?;
                for s in trailing {
                    seq.serialize_element(s)?;
                }
                seq.end()
            }
            Tag::Delegation {
                pubkey,
                conditions,
                sig,
                trailing,
            } => {
                let mut seq = serializer.serialize_seq(None)?;
                seq.serialize_element("delegation")?;
                seq.serialize_element(pubkey)?;
                seq.serialize_element(conditions)?;
                seq.serialize_element(sig)?;
                for s in trailing {
                    seq.serialize_element(s)?;
                }
                seq.end()
            }
            Tag::Event {
                id,
                recommended_relay_url,
                marker,
                trailing,
            } => {
                let mut seq = serializer.serialize_seq(None)?;
                seq.serialize_element("e")?;
                seq.serialize_element(id)?;
                if let Some(rru) = recommended_relay_url {
                    seq.serialize_element(rru)?;
                } else if marker.is_some() || !trailing.is_empty() {
                    seq.serialize_element("")?;
                }
                if let Some(m) = marker {
                    seq.serialize_element(m)?;
                } else if !trailing.is_empty() {
                    seq.serialize_element("")?;
                }
                for s in trailing {
                    seq.serialize_element(s)?;
                }
                seq.end()
            }
            Tag::Expiration { time, trailing } => {
                let mut seq = serializer.serialize_seq(None)?;
                seq.serialize_element("expiration")?;
                seq.serialize_element(time)?;
                for s in trailing {
                    seq.serialize_element(s)?;
                }
                seq.end()
            }
            Tag::Pubkey {
                pubkey,
                recommended_relay_url,
                petname,
                trailing,
            } => {
                let mut seq = serializer.serialize_seq(None)?;
                seq.serialize_element("p")?;
                seq.serialize_element(pubkey)?;
                if let Some(rru) = recommended_relay_url {
                    seq.serialize_element(rru)?;
                } else if petname.is_some() || !trailing.is_empty() {
                    seq.serialize_element("")?;
                }
                if let Some(pn) = petname {
                    seq.serialize_element(pn)?;
                } else if !trailing.is_empty() {
                    seq.serialize_element("")?;
                }
                for s in trailing {
                    seq.serialize_element(s)?;
                }
                seq.end()
            }
            Tag::Hashtag { hashtag, trailing } => {
                let mut seq = serializer.serialize_seq(None)?;
                seq.serialize_element("t")?;
                seq.serialize_element(hashtag)?;
                for s in trailing {
                    seq.serialize_element(s)?;
                }
                seq.end()
            }
            Tag::Reference {
                url,
                marker,
                trailing,
            } => {
                let mut seq = serializer.serialize_seq(None)?;
                seq.serialize_element("r")?;
                seq.serialize_element(url)?;
                if let Some(m) = marker {
                    seq.serialize_element(m)?
                } else if !trailing.is_empty() {
                    seq.serialize_element("")?
                }
                for s in trailing {
                    seq.serialize_element(s)?;
                }
                seq.end()
            }
            Tag::Geohash { geohash, trailing } => {
                let mut seq = serializer.serialize_seq(None)?;
                seq.serialize_element("g")?;
                seq.serialize_element(geohash)?;
                for s in trailing {
                    seq.serialize_element(s)?;
                }
                seq.end()
            }
            Tag::Identifier { d, trailing } => {
                let mut seq = serializer.serialize_seq(None)?;
                seq.serialize_element("d")?;
                seq.serialize_element(d)?;
                for s in trailing {
                    seq.serialize_element(s)?;
                }
                seq.end()
            }
            Tag::Subject { subject, trailing } => {
                let mut seq = serializer.serialize_seq(None)?;
                seq.serialize_element("subject")?;
                seq.serialize_element(subject)?;
                for s in trailing {
                    seq.serialize_element(s)?;
                }
                seq.end()
            }
            Tag::Nonce {
                nonce,
                target,
                trailing,
            } => {
                let mut seq = serializer.serialize_seq(None)?;
                seq.serialize_element("nonce")?;
                seq.serialize_element(nonce)?;
                if let Some(t) = target {
                    seq.serialize_element(t)?;
                } else if !trailing.is_empty() {
                    seq.serialize_element("")?;
                }
                for s in trailing {
                    seq.serialize_element(s)?;
                }
                seq.end()
            }
            Tag::Parameter { param, trailing } => {
                let mut seq = serializer.serialize_seq(None)?;
                seq.serialize_element("parameter")?;
                seq.serialize_element(param)?;
                for s in trailing {
                    seq.serialize_element(s)?;
                }
                seq.end()
            }
            Tag::Title { title, trailing } => {
                let mut seq = serializer.serialize_seq(None)?;
                seq.serialize_element("title")?;
                seq.serialize_element(title)?;
                for s in trailing {
                    seq.serialize_element(s)?;
                }
                seq.end()
            }
            Tag::Other { tag, data } => {
                let mut seq = serializer.serialize_seq(None)?;
                seq.serialize_element(tag)?;
                for s in data.iter() {
                    seq.serialize_element(s)?;
                }
                seq.end()
            }
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
        if tagname == "a" {
            if let Some(a) = seq.next_element::<&str>()? {
                let relay_url: Option<UncheckedUrl> = seq.next_element()?;
                let mut trailing: Vec<String> = Vec::new();
                while let Some(s) = seq.next_element()? {
                    trailing.push(s);
                }

                let fail = || -> Tag {
                    match relay_url {
                        Some(ref url) => {
                            let mut fv = vec![a.to_string(), url.as_str().to_owned()];
                            fv.extend(trailing.clone());
                            Tag::Other {
                                tag: tagname.to_string(),
                                data: fv,
                            }
                        }
                        None => Tag::Other {
                            tag: tagname.to_string(),
                            data: vec![a.to_string()],
                        },
                    }
                };

                let parts: Vec<&str> = a.split(':').collect();
                if parts.len() < 3 {
                    return Ok(fail());
                }
                let kindnum: u32 = match parts[0].parse::<u32>() {
                    Ok(u) => u,
                    Err(_) => return Ok(fail()),
                };
                let kind: EventKind = From::from(kindnum);
                let pubkey: PublicKeyHex = match PublicKeyHex::try_from_str(parts[1]) {
                    Ok(pk) => pk,
                    Err(_) => return Ok(fail()),
                };
                Ok(Tag::Address {
                    kind,
                    pubkey,
                    d: parts[2].to_string(),
                    relay_url,
                    trailing,
                })
            } else {
                Ok(Tag::Other {
                    tag: tagname.to_string(),
                    data: vec![],
                })
            }
        } else if tagname == "content-warning" {
            let msg = match seq.next_element()? {
                Some(s) => s,
                None => {
                    return Ok(Tag::Other {
                        tag: tagname.to_string(),
                        data: vec![],
                    });
                }
            };
            let mut trailing: Vec<String> = Vec::new();
            while let Some(s) = seq.next_element()? {
                trailing.push(s);
            }
            Ok(Tag::ContentWarning {
                warning: msg,
                trailing,
            })
        } else if tagname == "delegation" {
            let pubkey: PublicKeyHex = match seq.next_element()? {
                Some(pk) => pk,
                None => {
                    return Ok(Tag::Other {
                        tag: tagname.to_string(),
                        data: vec![],
                    });
                }
            };
            let conditions: DelegationConditions = match seq.next_element()? {
                Some(c) => c,
                None => {
                    return Ok(Tag::Other {
                        tag: tagname.to_string(),
                        data: vec![pubkey.into_string()],
                    });
                }
            };
            let sig: SignatureHex = match seq.next_element()? {
                Some(s) => s,
                None => {
                    return Ok(Tag::Other {
                        tag: tagname.to_string(),
                        data: vec![pubkey.into_string(), conditions.as_string()],
                    });
                }
            };
            let mut trailing: Vec<String> = Vec::new();
            while let Some(s) = seq.next_element()? {
                trailing.push(s);
            }
            Ok(Tag::Delegation {
                pubkey,
                conditions,
                sig,
                trailing,
            })
        } else if tagname == "e" {
            let id: Id = match seq.next_element()? {
                Some(id) => id,
                None => {
                    return Ok(Tag::Other {
                        tag: tagname.to_string(),
                        data: vec![],
                    });
                }
            };
            let recommended_relay_url: Option<UncheckedUrl> = seq.next_element()?;
            let marker: Option<String> = seq.next_element()?;
            let mut trailing: Vec<String> = Vec::new();
            while let Some(s) = seq.next_element()? {
                trailing.push(s);
            }
            Ok(Tag::Event {
                id,
                recommended_relay_url,
                marker,
                trailing,
            })
        } else if tagname == "expiration" {
            let time = match seq.next_element()? {
                Some(t) => t,
                None => {
                    return Ok(Tag::Other {
                        tag: tagname.to_string(),
                        data: vec![],
                    });
                }
            };
            let mut trailing: Vec<String> = Vec::new();
            while let Some(s) = seq.next_element()? {
                trailing.push(s);
            }
            Ok(Tag::Expiration { time, trailing })
        } else if tagname == "p" {
            let pubkey: PublicKeyHex = match seq.next_element()? {
                Some(p) => p,
                None => {
                    return Ok(Tag::Other {
                        tag: tagname.to_string(),
                        data: vec![],
                    });
                }
            };
            let recommended_relay_url: Option<UncheckedUrl> = seq.next_element()?;
            let petname: Option<String> = seq.next_element()?;
            let mut trailing: Vec<String> = Vec::new();
            while let Some(s) = seq.next_element()? {
                trailing.push(s);
            }
            Ok(Tag::Pubkey {
                pubkey,
                recommended_relay_url,
                petname,
                trailing,
            })
        } else if tagname == "t" {
            let tag = match seq.next_element()? {
                Some(t) => t,
                None => {
                    return Ok(Tag::Other {
                        tag: tagname.to_string(),
                        data: vec![],
                    });
                }
            };
            let mut trailing: Vec<String> = Vec::new();
            while let Some(s) = seq.next_element()? {
                trailing.push(s);
            }
            Ok(Tag::Hashtag {
                hashtag: tag,
                trailing,
            })
        } else if tagname == "r" {
            let refr: UncheckedUrl = match seq.next_element()? {
                Some(r) => r,
                None => {
                    return Ok(Tag::Other {
                        tag: tagname.to_string(),
                        data: vec![],
                    });
                }
            };
            let marker: Option<String> = seq.next_element()?;
            let mut trailing: Vec<String> = Vec::new();
            while let Some(s) = seq.next_element()? {
                trailing.push(s);
            }
            Ok(Tag::Reference {
                url: refr,
                marker,
                trailing,
            })
        } else if tagname == "g" {
            let geo = match seq.next_element()? {
                Some(g) => g,
                None => {
                    return Ok(Tag::Other {
                        tag: tagname.to_string(),
                        data: vec![],
                    });
                }
            };
            let mut trailing: Vec<String> = Vec::new();
            while let Some(s) = seq.next_element()? {
                trailing.push(s);
            }
            Ok(Tag::Geohash {
                geohash: geo,
                trailing,
            })
        } else if tagname == "d" {
            let id = match seq.next_element()? {
                Some(id) => id,
                None => {
                    // Implicit empty value
                    return Ok(Tag::Identifier {
                        d: "".to_string(),
                        trailing: Vec::new(),
                    });
                }
            };
            let mut trailing: Vec<String> = Vec::new();
            while let Some(s) = seq.next_element()? {
                trailing.push(s);
            }
            Ok(Tag::Identifier { d: id, trailing })
        } else if tagname == "subject" {
            let sub = match seq.next_element()? {
                Some(s) => s,
                None => {
                    return Ok(Tag::Other {
                        tag: tagname.to_string(),
                        data: vec![],
                    });
                }
            };
            let mut trailing: Vec<String> = Vec::new();
            while let Some(s) = seq.next_element()? {
                trailing.push(s);
            }
            Ok(Tag::Subject {
                subject: sub,
                trailing,
            })
        } else if tagname == "nonce" {
            let nonce = match seq.next_element()? {
                Some(n) => n,
                None => {
                    return Ok(Tag::Other {
                        tag: tagname.to_string(),
                        data: vec![],
                    });
                }
            };
            let target: Option<String> = seq.next_element()?;
            let mut trailing: Vec<String> = Vec::new();
            while let Some(s) = seq.next_element()? {
                trailing.push(s);
            }
            Ok(Tag::Nonce {
                nonce,
                target,
                trailing,
            })
        } else if tagname == "parameter" {
            let param = match seq.next_element()? {
                Some(s) => s,
                None => "".to_owned(), // implicit parameter
            };
            let mut trailing: Vec<String> = Vec::new();
            while let Some(s) = seq.next_element()? {
                trailing.push(s);
            }
            Ok(Tag::Parameter { param, trailing })
        } else if tagname == "title" {
            let title = match seq.next_element()? {
                Some(s) => s,
                None => {
                    return Ok(Tag::Other {
                        tag: tagname.to_string(),
                        data: vec![],
                    });
                }
            };
            let mut trailing: Vec<String> = Vec::new();
            while let Some(s) = seq.next_element()? {
                trailing.push(s);
            }
            Ok(Tag::Title { title, trailing })
        } else {
            let mut data = Vec::new();
            loop {
                match seq.next_element()? {
                    None => {
                        return Ok(Tag::Other {
                            tag: tagname.to_string(),
                            data,
                        })
                    }
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

    #[test]
    fn test_a_tag() {
        let tag = Tag::Address {
            kind: EventKind::LongFormContent,
            pubkey: PublicKeyHex::mock_deterministic(),
            d: "Testing123".to_owned(),
            relay_url: Some(UncheckedUrl("wss://relay.mikedilger.com/".to_string())),
            trailing: Vec::new(),
        };
        let string = serde_json::to_string(&tag).unwrap();
        let tag2 = serde_json::from_str(&string).unwrap();
        assert_eq!(tag, tag2);

        let tag = Tag::Address {
            kind: EventKind::LongFormContent,
            pubkey: PublicKeyHex::mock_deterministic(),
            d: "Testing123".to_owned(),
            relay_url: None,
            trailing: Vec::new(),
        };
        let string = serde_json::to_string(&tag).unwrap();
        let tag2 = serde_json::from_str(&string).unwrap();
        assert_eq!(tag, tag2);
    }
}
