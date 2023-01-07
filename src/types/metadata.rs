use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Metadata about a user
///
/// Note: the value is an Option because some real-world data has been found to
/// contain JSON nulls as values, and we don't want deserialization of those
/// events to fail. We treat these in our get() function the same as if the key
/// did not exist.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Metadata(pub HashMap<String, Option<String>>);

impl Default for Metadata {
    fn default() -> Self {
        Self::new()
    }
}

impl Metadata {
    /// Create new empty Metadata
    pub fn new() -> Metadata {
        Metadata(HashMap::new())
    }

    /// Get a key's value
    pub fn get(&self, key: &str) -> Option<String> {
        match self.0.get(key).cloned() {
            Some(Some(s)) => Some(s),
            Some(None) => None,
            None => None,
        }
    }

    /// Set a key's value
    pub fn set(&mut self, key: String, value: String) {
        let _ = self.0.insert(key, Some(value));
    }

    // Mock data for testing
    #[allow(dead_code)]
    pub(crate) fn mock() -> Metadata {
        let mut ext = Metadata::new();
        ext.set("website".to_owned(), "https://example.com".to_owned());
        ext.set("name".to_owned(), "Mike".to_owned());
        ext
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
    fn test_metadata_get_set() {
        let mut m = Metadata::new();
        m.set("name".to_owned(), "Mike".to_owned());
        assert_eq!(m.get("name"), Some("Mike".to_owned()));
        assert_eq!(m.get("motorcycle"), None);
    }

    #[test]
    fn test_tolerate_nulls() {
        let json = r##"{"name":"monlovesmango","picture":"https://astral.ninja/aura/monlovesmango.svg","about":"building on nostr","nip05":"monlovesmango@astral.ninja","lud06":null}"##;
        let m: Metadata = serde_json::from_str(&json).unwrap();
        assert_eq!(m.get("lud06"), None);
        assert_eq!(m.get("motorcycle"), None);
        assert_eq!(m.get("name"), Some("monlovesmango".to_string()));
    }
}
