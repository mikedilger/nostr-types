use super::{EventKind, IdHex, PublicKeyHex, Unixtime};
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::ops::Deref;

/// Filters which specify what events a client is looking for
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Filters {
    /// Events which match these ids
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[serde(default)]
    pub ids: Vec<IdHex>, // ID as hex, or prefix thereof

    /// Events which match these authors
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[serde(default)]
    pub authors: Vec<PublicKeyHex>, // PublicKey as hex, or prefix thereof

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

impl Filters {
    /// Create a new Filters object
    pub fn new() -> Filters {
        Default::default()
    }

    /// Add an Id (or prefix) to the filter.
    /// `prefix_length` is measured in hex characters
    pub fn add_id(&mut self, id_hex: &IdHex, prefix_length: Option<usize>) {
        let new_id = if let Some(mut len) = prefix_length {
            if len > 64 {
                len = 64
            }
            IdHex(id_hex[..len].to_owned())
        } else {
            id_hex.to_owned()
        };

        add_substr(&mut self.ids, new_id);
    }

    /// Delete an Id (or prefix) from the filter
    /// `prefix_length` is measured in hex characters
    pub fn del_id(&mut self, id_hex: &IdHex, prefix_length: Option<usize>) {
        let to_remove = if let Some(mut len) = prefix_length {
            if len > 64 {
                len = 64
            }
            IdHex(id_hex[..len].to_owned())
        } else {
            id_hex.to_owned()
        };

        del_substr(&mut self.ids, to_remove);
    }

    /// Add a PublicKey (or prefix) to the filter
    /// `prefix_length` is measured in hex characters
    pub fn add_author(&mut self, public_key_hex: &PublicKeyHex, prefix_length: Option<usize>) {
        let new_author = if let Some(mut len) = prefix_length {
            if len > 64 {
                len = 64
            }
            PublicKeyHex(public_key_hex[..len].to_owned())
        } else {
            public_key_hex.to_owned()
        };

        add_substr(&mut self.authors, new_author);
    }

    /// Delete a PublicKey (or prefix) from the filter
    /// `prefix_length` is measured in hex characters
    pub fn del_author(&mut self, public_key_hex: &PublicKeyHex, prefix_length: Option<usize>) {
        let to_remove = if let Some(mut len) = prefix_length {
            if len > 64 {
                len = 64
            }
            PublicKeyHex(public_key_hex[..len].to_owned())
        } else {
            public_key_hex.to_owned()
        };

        del_substr(&mut self.authors, to_remove);
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
    pub(crate) fn mock() -> Filters {
        Filters {
            ids: vec![IdHex("21345".to_string())],
            authors: vec![],
            kinds: vec![EventKind::TextNote, EventKind::Metadata],
            e: vec![IdHex::mock()],
            p: vec![PublicKeyHex("221115830ced1ca94352002485fcc7a75dcfe30d1b07f5f6fbe9c0407cfa59a1".to_owned())],
            since: Some(Unixtime(1668572286)),
            until: None,
            limit: None,
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    test_serde! {Filters, test_filters_serde}

    #[test]
    fn test_mock() {
        assert_eq!(
            &serde_json::to_string(&Filter::mock()).unwrap(),
            r##"{"ids":["21345"],"kinds":[1,0],"#e":["5df64b33303d62afc799bdc36d178c07b2e1f0d824f31b7dc812219440affab6"],"#p":["221115830ced1ca94352002485fcc7a75dcfe30d1b07f5f6fbe9c0407cfa59a1"],"since":1668572286}"##
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

        let mut filters: Filters = Filters::new();
        filters.add_id(&mock, Some(20));
        assert_eq!(filters.ids.len(), 1);
        filters.add_id(&mock, None); // overwrites
        assert_eq!(filters.ids.len(), 1);
        filters.del_id(&mock, None);
        assert!(filters.ids.is_empty());

        let mut filters: Filters = Filters::new();
        filters.add_id(&mock, Some(20));
        assert_eq!(filters.ids.len(), 1);
        filters.del_id(&mock, None); // keeps because it is shorter
        assert_eq!(filters.ids.len(), 1);
        filters.del_id(&mock, Some(20)); // now it deletes
        assert_eq!(filters.ids.len(), 0);

        let base_hex =
            IdHex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".to_string());
        let diff_hex =
            IdHex("ffffffffffffffffffffffffffffffffffffffffffff00000000000000000000".to_string());

        let mut filters: Filters = Filters::new();
        filters.add_id(&base_hex, Some(25));
        filters.add_id(&diff_hex, Some(25));
        filters.del_id(&base_hex, Some(10));
        assert_eq!(filters.ids.len(), 0); // deletes both since both match the 10-prefix

        filters.add_id(&base_hex, Some(3000));
    }

    // add_remove_author would be very similar to the above
}
