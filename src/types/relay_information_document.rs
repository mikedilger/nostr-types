use super::{EventKind, EventKindOrRange, PublicKeyHexPrefix, Url};
use serde::de::Error as DeError;
use serde::de::{Deserializer, MapAccess, Visitor};
use serde::ser::{SerializeMap, Serializer};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use std::fmt;

/// Relay limitations
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RelayLimitation {
    /// max message length
    pub max_message_length: usize,

    /// max subscriptions
    pub max_subscriptions: usize,

    /// max filters
    pub max_filters: usize,

    /// max limit
    pub max_limit: usize,

    /// max subid length
    pub max_subid_length: usize,

    /// min prefix
    pub min_prefix: usize,

    /// max event tags
    pub max_event_tags: usize,

    /// max content length
    pub max_content_length: usize,

    /// min pow difficulty
    pub min_pow_difficulty: usize,

    /// auth required
    pub auth_required: bool,

    /// payment required
    pub payment_required: bool,
}

/// Relay retention
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RelayRetention {
    /// kinds
    pub kinds: Option<Vec<EventKindOrRange>>,

    /// time
    pub time: Option<usize>,

    /// count
    pub count: Option<usize>,
}

/// Fee
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Fee {
    /// Amount of the fee
    pub amount: usize,

    /// Unit of the amount
    pub unit: String,

    /// Kinds of events
    pub kinds: Option<Vec<EventKindOrRange>>,

    /// Period purchase lasts for
    pub period: Option<usize>,
}

/// Relay fees
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RelayFees {
    /// Admission fee (read and write)
    pub admission: Vec<Fee>,

    /// Subscription fee (read)
    pub subscription: Vec<Fee>,

    /// Publication fee (write)
    pub publication: Vec<Fee>,
}

/// Relay information document as described in NIP-11, supplied by a relay
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelayInformationDocument {
    /// Name of the relay
    pub name: Option<String>,

    /// Description of the relay in plain text
    pub description: Option<String>,

    /// Public key of an administrative contact of the relay
    pub pubkey: Option<PublicKeyHexPrefix>,

    /// An administrative contact for the relay. Should be a URI.
    pub contact: Option<String>,

    /// A list of NIPs supported by the relay
    pub supported_nips: Vec<u32>,

    /// The software running the relay
    pub software: Option<String>,

    /// The software version
    pub version: Option<String>,

    /// limitation
    pub limitation: Option<RelayLimitation>,

    /// retention
    pub retention: Option<Vec<RelayRetention>>,

    /// content limitation: relay countries
    pub relay_countries: Option<Vec<String>>,

    /// community preferences: language tags
    pub language_tags: Option<Vec<String>>,

    /// community preferences: tags
    pub tags: Option<Vec<String>>,

    /// community preferences: posting policy
    pub posting_policy: Option<Url>,

    /// payments_url
    pub payments_url: Option<Url>,

    /// fees
    pub fees: Option<RelayFees>,

    /// Additional fields not specified in NIP-11
    pub other: Map<String, Value>,
}

impl Default for RelayInformationDocument {
    fn default() -> RelayInformationDocument {
        RelayInformationDocument {
            name: None,
            description: None,
            pubkey: None,
            contact: None,
            supported_nips: vec![],
            software: None,
            version: None,
            limitation: None,
            retention: None,
            relay_countries: None,
            language_tags: None,
            tags: None,
            posting_policy: None,
            payments_url: None,
            fees: None,
            other: Map::new(),
        }
    }
}

impl RelayInformationDocument {
    /// If the relay supports the queried `nip`
    pub fn supports_nip(&self, nip: u32) -> bool {
        self.supported_nips.contains(&nip)
    }

    #[allow(dead_code)]
    pub(crate) fn mock() -> RelayInformationDocument {
        let mut m = Map::new();
        let _ = m.insert(
            "early_nips".to_string(),
            Value::Array(vec![
                Value::Number(5.into()),
                Value::Number(6.into()),
                Value::Number(7.into()),
            ]),
        );
        RelayInformationDocument {
            name: Some("Crazy Horse".to_string()),
            description: Some("A really wild horse".to_string()),
            pubkey: Some(PublicKeyHexPrefix::mock()),
            contact: None,
            supported_nips: vec![11, 12, 13, 14],
            software: None,
            version: None,
            limitation: Some(RelayLimitation {
                max_message_length: 16384,
                max_subscriptions: 20,
                max_filters: 100,
                max_limit: 5000,
                max_subid_length: 100,
                min_prefix: 4,
                max_event_tags: 100,
                max_content_length: 8196,
                min_pow_difficulty: 30,
                auth_required: true,
                payment_required: true,
            }),
            retention: Some(vec![
                RelayRetention {
                    kinds: Some(vec![
                        EventKindOrRange::EventKind(EventKind::Metadata),
                        EventKindOrRange::EventKind(EventKind::TextNote),
                        EventKindOrRange::Range(vec![
                            EventKind::EventDeletion,
                            EventKind::Reaction,
                        ]),
                        EventKindOrRange::Range(vec![
                            EventKind::ChannelCreation,
                            EventKind::PublicChatReserved49,
                        ]),
                    ]),
                    time: Some(3600),
                    count: None,
                },
                RelayRetention {
                    kinds: Some(vec![EventKindOrRange::Range(vec![
                        EventKind::Other(40000),
                        EventKind::Other(49999),
                    ])]),
                    time: Some(100),
                    count: None,
                },
                RelayRetention {
                    kinds: Some(vec![EventKindOrRange::Range(vec![
                        EventKind::Other(30000),
                        EventKind::Other(39999),
                    ])]),
                    time: None,
                    count: Some(1000),
                },
                RelayRetention {
                    kinds: None,
                    time: Some(3600),
                    count: Some(10000),
                },
            ]),
            relay_countries: Some(vec!["CA".to_owned(), "US".to_owned()]),
            language_tags: Some(vec!["en".to_owned()]),
            tags: Some(vec!["sfw-only".to_owned(), "bitcoin-only".to_owned()]),
            posting_policy: Some(
                Url::try_from_str("https://example.com/posting-policy.html").unwrap(),
            ),
            payments_url: Some(Url::try_from_str("https://example.com/payments").unwrap()),
            fees: Some(RelayFees {
                admission: vec![Fee {
                    amount: 1000000,
                    unit: "msats".to_owned(),
                    kinds: None,
                    period: None,
                }],
                subscription: vec![Fee {
                    amount: 5000000,
                    unit: "msats".to_owned(),
                    kinds: None,
                    period: Some(2592000),
                }],
                publication: vec![Fee {
                    amount: 100,
                    unit: "msats".to_owned(),
                    kinds: Some(vec![EventKindOrRange::EventKind(EventKind::EventDeletion)]),
                    period: None,
                }],
            }),
            other: m,
        }
    }
}

impl fmt::Display for RelayInformationDocument {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Relay Information:")?;
        if let Some(name) = &self.name {
            write!(f, " Name=\"{name}\"")?;
        }
        if let Some(desc) = &self.description {
            write!(f, " Description=\"{desc}\"")?;
        }
        if let Some(pubkey) = &self.pubkey {
            write!(f, " Pubkey=\"{pubkey}\"")?;
        }
        if let Some(contact) = &self.contact {
            write!(f, " Contact=\"{contact}\"")?;
        }
        write!(f, " NIPS={:?}", self.supported_nips)?;
        if let Some(software) = &self.software {
            write!(f, " Software=\"{software}\"")?;
        }
        if let Some(version) = &self.version {
            write!(f, " Version=\"{version}\"")?;
        }
        for (k, v) in self.other.iter() {
            write!(f, " {k}=\"{v}\"")?;
        }
        Ok(())
    }
}

impl Serialize for RelayInformationDocument {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut map = serializer.serialize_map(Some(7 + self.other.len()))?;
        map.serialize_entry("name", &json!(&self.name))?;
        map.serialize_entry("description", &json!(&self.description))?;
        map.serialize_entry("pubkey", &json!(&self.pubkey))?;
        map.serialize_entry("contact", &json!(&self.contact))?;
        map.serialize_entry("supported_nips", &json!(&self.supported_nips))?;
        map.serialize_entry("software", &json!(&self.software))?;
        map.serialize_entry("version", &json!(&self.version))?;
        map.serialize_entry("limitation", &json!(&self.limitation))?;
        map.serialize_entry("retention", &json!(&self.retention))?;
        map.serialize_entry("relay_countries", &json!(&self.relay_countries))?;
        map.serialize_entry("language_tags", &json!(&self.language_tags))?;
        map.serialize_entry("tags", &json!(&self.tags))?;
        map.serialize_entry("posting_policy", &json!(&self.posting_policy))?;
        map.serialize_entry("payments_url", &json!(&self.payments_url))?;
        map.serialize_entry("fees", &json!(&self.fees))?;
        for (k, v) in &self.other {
            map.serialize_entry(&k, &v)?;
        }
        map.end()
    }
}

impl<'de> Deserialize<'de> for RelayInformationDocument {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_map(RidVisitor)
    }
}

struct RidVisitor;

impl<'de> Visitor<'de> for RidVisitor {
    type Value = RelayInformationDocument;

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "A JSON object")
    }

    fn visit_map<M>(self, mut access: M) -> Result<RelayInformationDocument, M::Error>
    where
        M: MapAccess<'de>,
    {
        let mut map: Map<String, Value> = Map::new();
        while let Some((key, value)) = access.next_entry::<String, Value>()? {
            let _ = map.insert(key, value);
        }

        let mut rid: RelayInformationDocument = Default::default();

        if let Some(Value::String(s)) = map.remove("name") {
            rid.name = Some(s);
        }
        if let Some(Value::String(s)) = map.remove("description") {
            rid.description = Some(s);
        }
        if let Some(Value::String(s)) = map.remove("pubkey") {
            rid.pubkey = match PublicKeyHexPrefix::try_from_string(s) {
                Ok(pkh) => Some(pkh),
                Err(e) => return Err(DeError::custom(format!("{e}"))),
            };
        }
        if let Some(Value::String(s)) = map.remove("contact") {
            rid.contact = Some(s);
        }
        if let Some(Value::Array(vec)) = map.remove("supported_nips") {
            for elem in vec.iter() {
                if let Value::Number(num) = elem {
                    if let Some(u) = num.as_u64() {
                        rid.supported_nips.push(u as u32);
                    }
                }
            }
        }
        if let Some(Value::String(s)) = map.remove("software") {
            rid.software = Some(s);
        }
        if let Some(Value::String(s)) = map.remove("version") {
            rid.version = Some(s);
        }
        if let Some(v) = map.remove("limitation") {
            rid.limitation = match serde_json::from_value::<Option<RelayLimitation>>(v) {
                Ok(x) => x,
                Err(e) => return Err(DeError::custom(format!("{e}"))),
            }
        }
        if let Some(v) = map.remove("retention") {
            rid.retention = match serde_json::from_value::<Option<Vec<RelayRetention>>>(v) {
                Ok(x) => x,
                Err(e) => return Err(DeError::custom(format!("{e}"))),
            };
        }
        if let Some(v) = map.remove("relay_countries") {
            rid.relay_countries = match serde_json::from_value::<Option<Vec<String>>>(v) {
                Ok(x) => x,
                Err(e) => return Err(DeError::custom(format!("{e}"))),
            }
        }
        if let Some(v) = map.remove("language_tags") {
            rid.language_tags = match serde_json::from_value::<Option<Vec<String>>>(v) {
                Ok(x) => x,
                Err(e) => return Err(DeError::custom(format!("{e}"))),
            }
        }
        if let Some(v) = map.remove("tags") {
            rid.tags = match serde_json::from_value::<Option<Vec<String>>>(v) {
                Ok(x) => x,
                Err(e) => return Err(DeError::custom(format!("{e}"))),
            }
        }
        if let Some(v) = map.remove("posting_policy") {
            rid.posting_policy = match serde_json::from_value::<Option<Url>>(v) {
                Ok(x) => x,
                Err(e) => return Err(DeError::custom(format!("{e}"))),
            }
        }
        if let Some(v) = map.remove("payments_url") {
            rid.payments_url = match serde_json::from_value::<Option<Url>>(v) {
                Ok(x) => x,
                Err(e) => return Err(DeError::custom(format!("{e}"))),
            }
        }
        if let Some(v) = map.remove("fees") {
            rid.fees = match serde_json::from_value::<Option<RelayFees>>(v) {
                Ok(x) => x,
                Err(e) => return Err(DeError::custom(format!("{e}"))),
            }
        }

        rid.other = map;

        Ok(rid)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    test_serde! {RelayInformationDocument, test_relay_information_document_serde}

    /*
        #[test]
        fn test_to_json_only() {
            let mock = RelayInformationDocument::mock();
            let s = serde_json::to_string(&mock).unwrap();
            println!("{}", s);
    }
        */

    #[test]
    fn test_relay_information_document_json() {
        let json = r##"{ "name": "A Relay", "description": null, "myfield": [1,2], "supported_nips": [11,12], "retention": [
    { "kinds": [0, 1, [5, 7], [40, 49]], "time": 3600 },
    { "kinds": [[40000, 49999]], "time": 100 },
    { "kinds": [[30000, 39999]], "count": 1000 },
    { "time": 3600, "count": 10000 }
  ] }"##;
        let rid: RelayInformationDocument = serde_json::from_str(json).unwrap();
        let json2 = serde_json::to_string(&rid).unwrap();
        let expected_json2 = r##"{"name":"A Relay","description":null,"pubkey":null,"contact":null,"supported_nips":[11,12],"software":null,"version":null,"limitation":null,"retention":[{"count":null,"kinds":[0,1,[5,7],[40,49]],"time":3600},{"count":null,"kinds":[[40000,49999]],"time":100},{"count":1000,"kinds":[[30000,39999]],"time":null},{"count":10000,"kinds":null,"time":3600}],"relay_countries":null,"language_tags":null,"tags":null,"posting_policy":null,"payments_url":null,"fees":null,"myfield":[1,2]}"##;
        assert_eq!(json2, expected_json2);
    }
}
