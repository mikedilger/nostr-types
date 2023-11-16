use crate::types::UncheckedUrl;
use serde::de::{Deserializer, MapAccess, Visitor};
use serde::ser::{SerializeMap, Serializer};
use serde::{Deserialize, Serialize};
#[cfg(feature = "speedy")]
use speedy::{Readable, Writable};
use std::collections::HashMap;
use std::fmt;

/// When and how to use a Relay
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "speedy", derive(Readable, Writable))]
pub struct SimpleRelayUsageV1 {
    /// Whether to write to this relay
    pub write: bool,

    /// Whether to read from this relay
    pub read: bool,
}

impl Default for SimpleRelayUsageV1 {
    fn default() -> SimpleRelayUsageV1 {
        SimpleRelayUsageV1 {
            write: false,
            read: true,
        }
    }
}

/// A list of relays with SimpleRelayUsageV1
#[derive(Clone, Debug, Default, Eq, PartialEq)]
#[cfg_attr(feature = "speedy", derive(Readable, Writable))]
pub struct SimpleRelayListV1(pub HashMap<UncheckedUrl, SimpleRelayUsageV1>);

impl SimpleRelayListV1 {
    #[allow(dead_code)]
    pub(crate) fn mock() -> SimpleRelayListV1 {
        let mut map: HashMap<UncheckedUrl, SimpleRelayUsageV1> = HashMap::new();
        let _ = map.insert(
            UncheckedUrl::from_str("wss://nostr.oxtr.dev"),
            SimpleRelayUsageV1 {
                write: true,
                read: true,
            },
        );
        let _ = map.insert(
            UncheckedUrl::from_str("wss://nostr-relay.wlvs.space"),
            SimpleRelayUsageV1 {
                write: false,
                read: true,
            },
        );
        SimpleRelayListV1(map)
    }
}

impl Serialize for SimpleRelayListV1 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut map = serializer.serialize_map(Some(self.0.len()))?;
        for (k, v) in &self.0 {
            map.serialize_entry(&k, &v)?;
        }
        map.end()
    }
}

impl<'de> Deserialize<'de> for SimpleRelayListV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_map(SimpleRelayListV1Visitor)
    }
}

struct SimpleRelayListV1Visitor;

impl<'de> Visitor<'de> for SimpleRelayListV1Visitor {
    type Value = SimpleRelayListV1;

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "A JSON object")
    }

    fn visit_map<M>(self, mut access: M) -> Result<SimpleRelayListV1, M::Error>
    where
        M: MapAccess<'de>,
    {
        let mut map: HashMap<UncheckedUrl, SimpleRelayUsageV1> = HashMap::new();
        while let Some((key, value)) = access.next_entry::<UncheckedUrl, SimpleRelayUsageV1>()? {
            let _ = map.insert(key, value);
        }
        Ok(SimpleRelayListV1(map))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    test_serde! {SimpleRelayListV1, test_simple_relay_list_serde}

    #[test]
    fn test_simple_relay_list_json() {
        let serialized = r#"{"wss://nostr.oxtr.dev":{"write":true,"read":true},"wss://relay.damus.io":{"write":true,"read":true},"wss://nostr.fmt.wiz.biz":{"write":true,"read":true},"wss://nostr-relay.wlvs.space":{"write":true,"read":true}}"#;
        let _simple_relay_list: SimpleRelayListV1 = serde_json::from_str(serialized).unwrap();
    }
}
