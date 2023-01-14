use serde::de::{Deserialize, Deserializer, MapAccess, Visitor};
use serde::ser::{Serialize, SerializeMap, Serializer};
use serde_json::{json, Map, Value};
use std::fmt;

/// Metadata about a user
///
/// Note: the value is an Option because some real-world data has been found to
/// contain JSON nulls as values, and we don't want deserialization of those
/// events to fail. We treat these in our get() function the same as if the key
/// did not exist.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Metadata {
    /// username
    pub name: Option<String>,

    /// about
    pub about: Option<String>,

    /// picture URL
    pub picture: Option<String>,

    /// nip05 dns id
    pub nip05: Option<String>,

    /// Additional fields not specified in NIP-01 or NIP-05
    pub other: Map<String, Value>,
}

impl Default for Metadata {
    fn default() -> Self {
        Metadata {
            name: None,
            about: None,
            picture: None,
            nip05: None,
            other: Map::new(),
        }
    }
}

impl Metadata {
    /// Create new empty Metadata
    pub fn new() -> Metadata {
        Metadata::default()
    }

    #[allow(dead_code)]
    pub(crate) fn mock() -> Metadata {
        let mut map = Map::new();
        let _ = map.insert(
            "display_name".to_string(),
            Value::String("William Caserin".to_string())
        );
        Metadata {
            name: Some("jb55".to_owned()),
            about: None,
            picture: None,
            nip05: Some("jb55.com".to_owned()),
            other: map
        }
    }
}

impl Serialize for Metadata {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut map = serializer.serialize_map(Some(4 + self.other.len()))?;
        map.serialize_entry("name", &json!(&self.name))?;
        map.serialize_entry("about", &json!(&self.about))?;
        map.serialize_entry("picture", &json!(&self.picture))?;
        map.serialize_entry("nip05", &json!(&self.nip05))?;
        for (k, v) in &self.other {
            map.serialize_entry(&k, &v)?;
        }
        map.end()
    }
}

impl<'de> Deserialize<'de> for Metadata {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_map(MetadataVisitor)
    }
}

struct MetadataVisitor;

impl<'de> Visitor<'de> for MetadataVisitor {
    type Value = Metadata;

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "A JSON object")
    }

    fn visit_map<M>(self, mut access: M) -> Result<Metadata, M::Error>
    where
        M: MapAccess<'de>,
    {
        let mut map: Map<String, Value> = Map::new();
        while let Some((key, value)) = access.next_entry::<String, Value>()? {
            let _ = map.insert(key, value);
        }

        let mut m: Metadata = Default::default();

        if let Some(Value::String(s)) = map.remove("name") {
            m.name = Some(s);
        }
        if let Some(Value::String(s)) = map.remove("about") {
            m.about = Some(s);
        }
        if let Some(Value::String(s)) = map.remove("picture") {
            m.picture = Some(s);
        }
        if let Some(Value::String(s)) = map.remove("nip05") {
            m.nip05 = Some(s);
        }

        m.other = map;

        Ok(m)
    }
}


#[cfg(test)]
mod test {
    use super::*;

    test_serde! {Metadata, test_metadata_serde}

    #[test]
    fn test_metadata_print_json() {
        // I want to see if JSON serialized metadata is network appropriate
        let m = Metadata::mock();
        println!("{}", serde_json::to_string(&m).unwrap());
    }

    #[test]
    fn test_tolerate_nulls() {
        let json = r##"{"name":"monlovesmango","picture":"https://astral.ninja/aura/monlovesmango.svg","about":"building on nostr","nip05":"monlovesmango@astral.ninja","lud06":null,"testing":"123"}"##;
        let m: Metadata = serde_json::from_str(&json).unwrap();
        assert_eq!(m.name, Some("monlovesmango".to_owned()));
        assert_eq!(m.other.get("lud06"), Some(&Value::Null));
        assert_eq!(m.other.get("testing"), Some(&Value::String("123".to_owned())));
    }
}
