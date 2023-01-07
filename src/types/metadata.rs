use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Metadata about a user
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Metadata(pub HashMap<String, String>);

impl Metadata {
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
    fn print_metadata_json() {
        // I want to see if JSON serialized metadata is network appropriate
        let m = Metadata::mock();
        println!("{}", serde_json::to_string(&m).unwrap());
    }
}
