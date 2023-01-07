use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Metadata about a user
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Metadata(pub HashMap<String, String>);

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
        self.0.get(key).cloned()
    }

    /// Set a key's value
    pub fn set(&mut self, key: String, value: String) {
        let _ = self.0.insert(key, value);
    }

    // Mock data for testing
    #[allow(dead_code)]
    pub(crate) fn mock() -> Metadata {
        let mut ext = HashMap::new();
        let _ = ext.insert("website".to_owned(), "https://example.com".to_owned());
        let _ = ext.insert("name".to_owned(), "Mike".to_owned());
        Metadata(ext)
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
}
