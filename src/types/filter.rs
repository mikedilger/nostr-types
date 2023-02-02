use super::{EventKind, IdHex, IdHexPrefix, PublicKeyHex, PublicKeyHexPrefix, Unixtime};
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::ops::Deref;

/// Filter which specify what events a client is looking for
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Filter {
    /// Events which match these ids
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[serde(default)]
    pub ids: Vec<IdHexPrefix>, // ID as hex, or prefix thereof

    /// Events which match these authors
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[serde(default)]
    pub authors: Vec<PublicKeyHexPrefix>, // PublicKey as hex, or prefix thereof

    /// Events which match these kinds
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[serde(default)]
    pub kinds: Vec<EventKind>,

    /// Events when referenced in an 'e' tag
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[serde(rename = "#e")]
    #[serde(default)]
    pub e: Vec<IdHex>,

    /// Events when referenced in a 'p' tag
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[serde(rename = "#p")]
    #[serde(default)]
    pub p: Vec<PublicKeyHex>,

    /// Events occuring after this date
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub since: Option<Unixtime>,

    /// Events occuring before this date
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub until: Option<Unixtime>,

    /// A limit on the number of events to return in the initial query
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub limit: Option<usize>,
}

#[derive(Debug, PartialEq, Eq)]
enum PrefixMatch {
    Longer,
    Shorter,
    Equal,
    Mismatch,
}

fn prefix_match(s1: &str, s2: &str) -> PrefixMatch {
    match s1.len().cmp(&s2.len()) {
        Ordering::Equal => {
            if s1 == s2 {
                PrefixMatch::Equal
            } else {
                PrefixMatch::Mismatch
            }
        }
        Ordering::Greater => {
            if &s1[..s2.len()] == s2 {
                PrefixMatch::Shorter
            } else {
                PrefixMatch::Mismatch
            }
        }
        Ordering::Less => {
            if s1 == &s2[..s1.len()] {
                PrefixMatch::Longer
            } else {
                PrefixMatch::Mismatch
            }
        }
    }
}

fn add_substr<T: Deref<Target = String>>(vec: &mut Vec<T>, add: T) {
    for (index, existing) in vec.iter().enumerate() {
        match prefix_match(existing, &add) {
            PrefixMatch::Equal | PrefixMatch::Shorter => return,
            PrefixMatch::Longer => {
                vec[index] = add;
                return;
            }
            PrefixMatch::Mismatch => {}
        }
    }

    vec.push(add);
}

fn del_substr<T: Deref<Target = String>>(vec: &mut Vec<T>, del: T) {
    let mut marked: Vec<usize> = Vec::new();
    for (index, existing) in vec.iter().enumerate() {
        match prefix_match(existing, &del) {
            PrefixMatch::Equal | PrefixMatch::Shorter => marked.push(index),
            _ => {}
        }
    }
    for index in marked.iter().rev() {
        let _ = vec.swap_remove(*index);
    }
}

impl Filter {
    /// Create a new Filter object
    pub fn new() -> Filter {
        Default::default()
    }

    /// Add an Id (or prefix) to the filter.
    /// `prefix_length` is measured in hex characters
    pub fn add_id<T: Into<IdHexPrefix>>(&mut self, id_hex_prefix: T) {
        add_substr(&mut self.ids, id_hex_prefix.into());
    }

    /// Delete an Id (or prefix) from the filter
    /// `prefix_length` is measured in hex characters
    pub fn del_id<T: Into<IdHexPrefix>>(&mut self, id_hex_prefix: T) {
        del_substr(&mut self.ids, id_hex_prefix.into());
    }

    /// Add a PublicKey (or prefix) to the filter
    /// `prefix_length` is measured in hex characters
    pub fn add_author<T: Into<PublicKeyHexPrefix>>(&mut self, public_key_hex_prefix: T) {
        add_substr(&mut self.authors, public_key_hex_prefix.into());
    }

    /// Delete a PublicKey (or prefix) from the filter
    /// `prefix_length` is measured in hex characters
    pub fn del_author<T: Into<PublicKeyHexPrefix>>(&mut self, public_key_hex_prefix: T) {
        del_substr(&mut self.authors, public_key_hex_prefix.into());
    }

    /// Add an EventKind to the filter
    pub fn add_event_kind(&mut self, event_kind: EventKind) {
        if self.kinds.contains(&event_kind) {
            return;
        }
        self.kinds.push(event_kind);
    }

    /// Delete an EventKind from the filter
    pub fn del_event_kind(&mut self, event_kind: EventKind) {
        if let Some(position) = self.kinds.iter().position(|&x| x == event_kind) {
            let _ = self.kinds.swap_remove(position);
        }
    }

    /// Add an e-tag Id to the filter
    pub fn add_e_tag_ids(&mut self, id_hex: IdHex) {
        if self.e.contains(&id_hex) {
            return;
        }
        self.e.push(id_hex);
    }

    /// Delete an e-tag Id from the filter
    pub fn del_e_tag_ids(&mut self, id_hex: &IdHex) {
        if let Some(position) = self.e.iter().position(|x| x == id_hex) {
            let _ = self.e.swap_remove(position);
        }
    }

    /// Add a PublicKey to the filter
    pub fn add_p_tag_public_key(&mut self, public_key_hex: PublicKeyHex) {
        if self.p.contains(&public_key_hex) {
            return;
        }
        self.p.push(public_key_hex);
    }

    /// Delete a PublicKey from the filter
    pub fn del_p_tag_public_key(&mut self, public_key_hex: &PublicKeyHex) {
        if let Some(position) = self.p.iter().position(|x| x == public_key_hex) {
            let _ = self.p.swap_remove(position);
        }
    }

    // Mock data for testing
    #[allow(dead_code)]
    pub(crate) fn mock() -> Filter {
        Filter {
            ids: vec![IdHexPrefix::try_from_str("21345b").unwrap()],
            authors: vec![],
            kinds: vec![EventKind::TextNote, EventKind::Metadata],
            e: vec![IdHex::mock()],
            p: vec![PublicKeyHex::try_from_str(
                "221115830ced1ca94352002485fcc7a75dcfe30d1b07f5f6fbe9c0407cfa59a1",
            )
            .unwrap()],
            since: Some(Unixtime(1668572286)),
            until: None,
            limit: None,
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    test_serde! {Filter, test_filters_serde}

    #[test]
    fn test_mock() {
        assert_eq!(
            &serde_json::to_string(&Filter::mock()).unwrap(),
            r##"{"ids":["21345b"],"kinds":[1,0],"#e":["5df64b33303d62afc799bdc36d178c07b2e1f0d824f31b7dc812219440affab6"],"#p":["221115830ced1ca94352002485fcc7a75dcfe30d1b07f5f6fbe9c0407cfa59a1"],"since":1668572286}"##
        );
    }

    #[test]
    fn test_prefix_match() {
        assert_eq!(prefix_match("1234", "123"), PrefixMatch::Shorter);
        assert_eq!(prefix_match("123", "1234"), PrefixMatch::Longer);
        assert_eq!(prefix_match("1234", "1234"), PrefixMatch::Equal);
        assert_eq!(prefix_match("1244", "123"), PrefixMatch::Mismatch);
        assert_eq!(prefix_match("124", "1234"), PrefixMatch::Mismatch);
        assert_eq!(prefix_match("1244", "1234"), PrefixMatch::Mismatch);
        assert_eq!(prefix_match("1234", "124"), PrefixMatch::Mismatch);
        assert_eq!(prefix_match("123", "1244"), PrefixMatch::Mismatch);
        assert_eq!(prefix_match("1234", "1244"), PrefixMatch::Mismatch);
    }

    #[test]
    fn test_add_remove_id() {
        let mock = IdHex::mock();

        let mut filters: Filter = Filter::new();

        filters.add_id(mock.prefix(20));
        assert_eq!(filters.ids.len(), 1);
        filters.add_id(mock.clone()); // overwrites
        assert_eq!(filters.ids.len(), 1);
        filters.del_id(mock.clone());
        assert!(filters.ids.is_empty());

        let mut filters: Filter = Filter::new();
        filters.add_id(mock.prefix(20));
        assert_eq!(filters.ids.len(), 1);
        filters.del_id(mock.clone()); // keeps because it is shorter
        assert_eq!(filters.ids.len(), 1);
        filters.del_id(mock.prefix(20)); // now it deletes
        assert_eq!(filters.ids.len(), 0);

        let base_hex =
            IdHex::try_from_str("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
                .unwrap();
        let diff_hex =
            IdHex::try_from_str("ffffffffffffffffffffffffffffffffffffffffffff00000000000000000000")
                .unwrap();

        let mut filters: Filter = Filter::new();
        filters.add_id(base_hex.prefix(25));
        filters.add_id(diff_hex.prefix(25));
        filters.del_id(base_hex.prefix(10));
        assert_eq!(filters.ids.len(), 0); // deletes both since both match the 10-prefix

        filters.add_id(base_hex.prefix(3000));
    }

    // add_remove_author would be very similar to the above
}
