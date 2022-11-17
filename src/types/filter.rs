use super::{EventKind, Id, PublicKey, Unixtime};
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;

/// Filters which specify what events a client is looking for
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Filters {
    /// Events which match these ids
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[serde(default)]
    pub ids: Vec<String>,

    /// Events which match these authors
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[serde(default)]
    pub authors: Vec<String>, // public key prefix

    /// Events which match these kinds
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[serde(default)]
    pub kinds: Vec<EventKind>,

    /// Events when referenced in an 'e' tag
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[serde(default)]
    pub e: Vec<Id>,

    /// Events when referenced in a 'p' tag
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[serde(default)]
    pub p: Vec<PublicKey>,

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

fn add_substr(vec: &mut Vec<String>, add: String) {
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

fn del_substr(vec: &mut Vec<String>, del: String) {
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
    pub fn add_id(&mut self, id: &Id, prefix_length: Option<usize>) {
        let new_id = if let Some(mut len) = prefix_length {
            if len > 64 {
                len = 64
            }
            id.as_hex_string()[..len].to_owned()
        } else {
            id.as_hex_string()
        };

        add_substr(&mut self.ids, new_id);
    }

    /// Delete an Id (or prefix) from the filter
    /// `prefix_length` is measured in hex characters
    pub fn del_id(&mut self, id: &Id, prefix_length: Option<usize>) {
        let to_remove = if let Some(mut len) = prefix_length {
            if len > 64 {
                len = 64
            }
            id.as_hex_string()[..len].to_owned()
        } else {
            id.as_hex_string()
        };

        del_substr(&mut self.ids, to_remove);
    }

    /// Add a PublicKey (or prefix) to the filter
    /// `prefix_length` is measured in hex characters
    pub fn add_author(&mut self, public_key: &PublicKey, prefix_length: Option<usize>) {
        let new_author = if let Some(mut len) = prefix_length {
            if len > 64 {
                len = 64
            }
            public_key.as_hex_string()[..len].to_owned()
        } else {
            public_key.as_hex_string()
        };

        add_substr(&mut self.authors, new_author);
    }

    /// Delete a PublicKey (or prefix) from the filter
    /// `prefix_length` is measured in hex characters
    pub fn del_author(&mut self, public_key: &PublicKey, prefix_length: Option<usize>) {
        let to_remove = if let Some(mut len) = prefix_length {
            if len > 64 {
                len = 64
            }
            public_key.as_hex_string()[..len].to_owned()
        } else {
            public_key.as_hex_string()
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
    pub fn add_e_tag_ids(&mut self, id: Id) {
        if self.e.contains(&id) {
            return;
        }
        self.e.push(id);
    }

    /// Delete an e-tag Id from the filter
    pub fn del_e_tag_ids(&mut self, id: &Id) {
        if let Some(position) = self.e.iter().position(|x| x == id) {
            let _ = self.e.swap_remove(position);
        }
    }

    /// Add a PublicKey to the filter
    pub fn add_p_tag_public_key(&mut self, public_key: PublicKey) {
        if self.p.contains(&public_key) {
            return;
        }
        self.p.push(public_key);
    }

    /// Delete a PublicKey from the filter
    pub fn del_p_tag_public_key(&mut self, public_key: &PublicKey) {
        if let Some(position) = self.p.iter().position(|x| x == public_key) {
            let _ = self.p.swap_remove(position);
        }
    }

    // Mock data for testing
    #[allow(dead_code)]
    pub(crate) fn mock() -> Filters {
        Filters {
            ids: vec!["21345".to_string()],
            authors: vec![],
            kinds: vec![EventKind::TextNote, EventKind::Metadata],
            e: vec![],
            p: vec![],
            since: Some(Unixtime::mock()),
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
        let mock = Id::mock();

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

        let base = Id([
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 31,
        ]);
        let diff = Id([
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0,
        ]);

        let mut filters: Filters = Filters::new();
        filters.add_id(&base, Some(25));
        filters.add_id(&diff, Some(25));
        filters.del_id(&base, Some(10));
        assert_eq!(filters.ids.len(), 0); // deletes both since both match the 10-prefix

        filters.add_id(&base, Some(3000));
    }

    // add_remove_author would be very similar to the above
}
