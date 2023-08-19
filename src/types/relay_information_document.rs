use super::{EventKind, EventKindOrRange, PublicKeyHexPrefix, Url};
//use serde::de::Error as DeError;
use serde::de::{Deserializer, MapAccess, Visitor};
use serde::ser::{SerializeMap, Serializer};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
#[cfg(feature = "speedy")]
use speedy::{Readable, Writable};
use std::fmt;

/// Relay limitations
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "speedy", derive(Readable, Writable))]
pub struct RelayLimitation {
    /// max message length
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub max_message_length: Option<usize>,

    /// max subscriptions
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub max_subscriptions: Option<usize>,

    /// max filters
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub max_filters: Option<usize>,

    /// max limit
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub max_limit: Option<usize>,

    /// max subid length
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub max_subid_length: Option<usize>,

    /// min prefix
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub min_prefix: Option<usize>,

    /// max event tags
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub max_event_tags: Option<usize>,

    /// max content length
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub max_content_length: Option<usize>,

    /// min pow difficulty
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub min_pow_difficulty: Option<usize>,

    /// auth required
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub auth_required: Option<bool>,

    /// payment required
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub payment_required: Option<bool>,
}

impl fmt::Display for RelayLimitation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Relay Limitation:")?;
        if let Some(mml) = &self.max_message_length {
            write!(f, " MaxMessageLength=\"{mml}\"")?;
        }
        if let Some(ms) = &self.max_subscriptions {
            write!(f, " MaxSubscriptions=\"{ms}\"")?;
        }
        if let Some(mf) = &self.max_filters {
            write!(f, " MaxFilters=\"{mf}\"")?;
        }
        if let Some(ml) = &self.max_limit {
            write!(f, " MaxLimit=\"{ml}\"")?;
        }
        if let Some(msil) = &self.max_subid_length {
            write!(f, " MaxSubidLength=\"{msil}\"")?;
        }
        if let Some(mp) = &self.min_prefix {
            write!(f, " MinPrefix=\"{mp}\"")?;
        }
        if let Some(met) = &self.max_event_tags {
            write!(f, " MaxEventTags=\"{met}\"")?;
        }
        if let Some(mcl) = &self.max_content_length {
            write!(f, " MaxContentLength=\"{mcl}\"")?;
        }
        if let Some(mpd) = &self.min_pow_difficulty {
            write!(f, " MinPowDifficulty=\"{mpd}\"")?;
        }
        if let Some(ar) = &self.auth_required {
            write!(f, " AuthRequired=\"{ar}\"")?;
        }
        if let Some(pr) = &self.payment_required {
            write!(f, " PaymentRequired=\"{pr}\"")?;
        }
        Ok(())
    }
}

/// Relay retention
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "speedy", derive(Readable, Writable))]
pub struct RelayRetention {
    /// kinds
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[serde(default)]
    pub kinds: Vec<EventKindOrRange>,

    /// time
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub time: Option<usize>,

    /// count
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub count: Option<usize>,
}

impl fmt::Display for RelayRetention {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Relay Retention:")?;
        write!(f, " Kinds=\"{:?}\"", self.kinds)?;
        if let Some(time) = &self.time {
            write!(f, " Time=\"{time}\"")?;
        }
        if let Some(count) = &self.count {
            write!(f, " Count=\"{count}\"")?;
        }
        Ok(())
    }
}

/// Fee
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "speedy", derive(Readable, Writable))]
pub struct Fee {
    /// Amount of the fee
    pub amount: usize,

    /// Unit of the amount
    pub unit: String,

    /// Kinds of events
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[serde(default)]
    pub kinds: Vec<EventKindOrRange>,

    /// Period purchase lasts for
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub period: Option<usize>,
}

impl fmt::Display for Fee {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Fee=[{} {}", self.amount, self.unit)?;
        write!(f, " Kinds=\"{:?}\"", self.kinds)?;
        if let Some(period) = &self.period {
            write!(f, " Period=\"{}\"", period)?;
        }
        write!(f, "]")
    }
}

/// Relay fees
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "speedy", derive(Readable, Writable))]
pub struct RelayFees {
    /// Admission fee (read and write)
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[serde(default)]
    pub admission: Vec<Fee>,

    /// Subscription fee (read)
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[serde(default)]
    pub subscription: Vec<Fee>,

    /// Publication fee (write)
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[serde(default)]
    pub publication: Vec<Fee>,
}

impl fmt::Display for RelayFees {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Relay Fees:")?;
        write!(f, " Admission=[")?;
        for fee in &self.admission {
            write!(f, "{} ", fee)?;
        }
        write!(f, "],Subscription=[")?;
        for fee in &self.subscription {
            write!(f, "{} ", fee)?;
        }
        write!(f, "],Publication=[")?;
        for fee in &self.publication {
            write!(f, "{} ", fee)?;
        }
        write!(f, "]")
    }
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
    pub retention: Vec<RelayRetention>,

    /// content limitation: relay countries
    pub relay_countries: Vec<String>,

    /// community preferences: language tags
    pub language_tags: Vec<String>,

    /// community preferences: tags
    pub tags: Vec<String>,

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
            retention: vec![],
            relay_countries: vec![],
            language_tags: vec![],
            tags: vec![],
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
                max_message_length: Some(16384),
                max_subscriptions: Some(20),
                max_filters: Some(100),
                max_limit: Some(5000),
                max_subid_length: Some(100),
                min_prefix: Some(4),
                max_event_tags: Some(100),
                max_content_length: Some(8196),
                min_pow_difficulty: Some(30),
                auth_required: Some(true),
                payment_required: Some(true),
            }),
            retention: vec![
                RelayRetention {
                    kinds: vec![
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
                    ],
                    time: Some(3600),
                    count: None,
                },
                RelayRetention {
                    kinds: vec![EventKindOrRange::Range(vec![
                        EventKind::Other(40000),
                        EventKind::Other(49999),
                    ])],
                    time: Some(100),
                    count: None,
                },
                RelayRetention {
                    kinds: vec![EventKindOrRange::Range(vec![
                        EventKind::CategorizedPeopleList,
                        EventKind::Other(39999),
                    ])],
                    time: None,
                    count: Some(1000),
                },
                RelayRetention {
                    kinds: vec![],
                    time: Some(3600),
                    count: Some(10000),
                },
            ],
            relay_countries: vec!["CA".to_owned(), "US".to_owned()],
            language_tags: vec!["en".to_owned()],
            tags: vec!["sfw-only".to_owned(), "bitcoin-only".to_owned()],
            posting_policy: Some(
                Url::try_from_str("https://example.com/posting-policy.html").unwrap(),
            ),
            payments_url: Some(Url::try_from_str("https://example.com/payments").unwrap()),
            fees: Some(RelayFees {
                admission: vec![Fee {
                    amount: 1000000,
                    unit: "msats".to_owned(),
                    kinds: vec![],
                    period: None,
                }],
                subscription: vec![Fee {
                    amount: 5000000,
                    unit: "msats".to_owned(),
                    kinds: vec![],
                    period: Some(2592000),
                }],
                publication: vec![Fee {
                    amount: 100,
                    unit: "msats".to_owned(),
                    kinds: vec![EventKindOrRange::EventKind(EventKind::EventDeletion)],
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
        if !self.supported_nips.is_empty() {
            write!(f, " NIPS={:?}", self.supported_nips)?;
        }
        if let Some(software) = &self.software {
            write!(f, " Software=\"{software}\"")?;
        }
        if let Some(version) = &self.version {
            write!(f, " Version=\"{version}\"")?;
        }
        if let Some(limitation) = &self.limitation {
            write!(f, " Limitation=\"{limitation}\"")?;
        }
        for retention in &self.retention {
            write!(f, " Retention=\"{retention}\"")?;
        }
        if !self.relay_countries.is_empty() {
            write!(f, " Countries=[")?;
            for country in &self.relay_countries {
                write!(f, "{country},")?;
            }
            write!(f, "]")?;
        }
        if !self.language_tags.is_empty() {
            write!(f, " Languages=[")?;
            for language in &self.language_tags {
                write!(f, "{language},")?;
            }
            write!(f, "]")?;
        }
        if !self.tags.is_empty() {
            write!(f, " Tags=[")?;
            for tag in &self.tags {
                write!(f, "{tag},")?;
            }
            write!(f, "]")?;
        }
        if let Some(policy_url) = &self.posting_policy {
            write!(f, " PostingPolicy={policy_url}")?;
        }
        if let Some(url) = &self.payments_url {
            write!(f, " PaymentsUrl={url}")?;
        }
        if let Some(fees) = &self.fees {
            write!(f, " Fees={fees}")?;
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
        if self.name.is_some() {
            map.serialize_entry("name", &json!(&self.name))?;
        }
        if self.description.is_some() {
            map.serialize_entry("description", &json!(&self.description))?;
        }
        if self.pubkey.is_some() {
            map.serialize_entry("pubkey", &json!(&self.pubkey))?;
        }
        if self.contact.is_some() {
            map.serialize_entry("contact", &json!(&self.contact))?;
        }
        map.serialize_entry("supported_nips", &json!(&self.supported_nips))?;
        if self.software.is_some() {
            map.serialize_entry("software", &json!(&self.software))?;
        }
        if self.version.is_some() {
            map.serialize_entry("version", &json!(&self.version))?;
        }
        if self.limitation.is_some() {
            map.serialize_entry("limitation", &json!(&self.limitation))?;
        }
        if !self.retention.is_empty() {
            map.serialize_entry("retention", &json!(&self.retention))?;
        }
        if !self.relay_countries.is_empty() {
            map.serialize_entry("relay_countries", &json!(&self.relay_countries))?;
        }
        if !self.language_tags.is_empty() {
            map.serialize_entry("language_tags", &json!(&self.language_tags))?;
        }
        if !self.tags.is_empty() {
            map.serialize_entry("tags", &json!(&self.tags))?;
        }
        if self.posting_policy.is_some() {
            map.serialize_entry("posting_policy", &json!(&self.posting_policy))?;
        }
        if self.payments_url.is_some() {
            map.serialize_entry("payments_url", &json!(&self.payments_url))?;
        }
        if self.fees.is_some() {
            map.serialize_entry("fees", &json!(&self.fees))?;
        }
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
                Err(_) => None,
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
                Err(_) => None,
            }
        }
        if let Some(v) = map.remove("retention") {
            rid.retention = match serde_json::from_value::<Vec<RelayRetention>>(v) {
                Ok(x) => x,
                Err(_) => vec![],
            };
        }
        if let Some(v) = map.remove("relay_countries") {
            rid.relay_countries = match serde_json::from_value::<Vec<String>>(v) {
                Ok(x) => x,
                Err(_) => vec![],
            }
        }
        if let Some(v) = map.remove("language_tags") {
            rid.language_tags = match serde_json::from_value::<Vec<String>>(v) {
                Ok(x) => x,
                Err(_) => vec![],
            }
        }
        if let Some(v) = map.remove("tags") {
            rid.tags = match serde_json::from_value::<Vec<String>>(v) {
                Ok(x) => x,
                Err(_) => vec![],
            }
        }
        if let Some(v) = map.remove("posting_policy") {
            rid.posting_policy = match serde_json::from_value::<Option<Url>>(v) {
                Ok(x) => x,
                Err(_) => None,
            }
        }
        if let Some(v) = map.remove("payments_url") {
            rid.payments_url = match serde_json::from_value::<Option<Url>>(v) {
                Ok(x) => x,
                Err(_) => None,
            }
        }
        if let Some(v) = map.remove("fees") {
            rid.fees = match serde_json::from_value::<Option<RelayFees>>(v) {
                Ok(x) => x,
                Err(_) => None,
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

    #[test]
    fn test_to_json_only() {
        // This is so you can see the JSON limitation.
        // Run with "cargo test toest_to_json_only -- --nocapture"
        let mock = RelayInformationDocument::mock();
        let s = serde_json::to_string(&mock).unwrap();
        println!("{}", s);
    }

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
        let expected_json2 = r##"{"name":"A Relay","supported_nips":[11,12],"retention":[{"kinds":[0,1,[5,7],[40,49]],"time":3600},{"kinds":[[40000,49999]],"time":100},{"count":1000,"kinds":[[30000,39999]]},{"count":10000,"time":3600}],"myfield":[1,2]}"##;
        assert_eq!(json2, expected_json2);
    }
}
