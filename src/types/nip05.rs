use super::{PublicKeyHex, Url};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// The content of a webserver's /.well-known/nostr.json file used in NIP-05 and NIP-35
/// This allows lookup and verification of a nostr user via a `user@domain` style identifier.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Nip05 {
    /// DNS names mapped to public keys
    pub names: HashMap<String, PublicKeyHex>,

    /// Public keys mapped to arrays of relays where they post
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    #[serde(default)]
    pub relays: HashMap<PublicKeyHex, Vec<Url>>,
}

impl Nip05 {
    // Mock data for testing
    #[allow(dead_code)]
    pub(crate) fn mock() -> Nip05 {
        let pubkey = PublicKeyHex(
            "b0635d6a9851d3aed0cd6c495b282167acf761729078d975fc341b22650b07b9".to_owned()
        );

        let mut names: HashMap<String, PublicKeyHex> = HashMap::new();
        let _ = names.insert("bob".to_string(), pubkey.clone());

        let mut relays: HashMap<PublicKeyHex, Vec<Url>> = HashMap::new();
        let _ = relays.insert(
            pubkey,
            vec![
                Url::new("wss://relay.example.com"),
                Url::new("wss://relay2.example.com"),
            ],
        );

        Nip05 { names, relays }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    test_serde! {Nip05, test_nip05_serde}

    #[test]
    fn test_nip05_example() {
        let body = r#"{
  "names": {
    "bob": "b0635d6a9851d3aed0cd6c495b282167acf761729078d975fc341b22650b07b9"
  },
  "relays": {
    "b0635d6a9851d3aed0cd6c495b282167acf761729078d975fc341b22650b07b9": [ "wss://relay.example.com", "wss://relay2.example.com" ]
  }
}"#;

        let nip05: Nip05 = serde_json::from_str(&body).unwrap();

        let bobs_pk: PublicKeyHex = nip05.names.get("bob").unwrap().clone();
        assert_eq!(
            &bobs_pk.0,
            "b0635d6a9851d3aed0cd6c495b282167acf761729078d975fc341b22650b07b9"
        );

        let bobs_relays: Vec<Url> = nip05.relays.get(&bobs_pk).unwrap().to_owned();

        assert_eq!(
            bobs_relays,
            vec![
                Url::new("wss://relay.example.com"),
                Url::new("wss://relay2.example.com")
            ]
        );
    }
}
