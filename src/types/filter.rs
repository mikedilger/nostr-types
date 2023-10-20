use super::{EventKind, IdHex, PublicKeyHex, Unixtime};
use serde::{Deserialize, Serialize};
#[cfg(feature = "speedy")]
use speedy::{Readable, Writable};

/// Filter which specify what events a client is looking for
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "speedy", derive(Readable, Writable))]
pub struct Filter {
    /// Events which match these ids
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[serde(default)]
    pub ids: Vec<IdHex>, // ID as hex

    /// Events which match these authors
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[serde(default)]
    pub authors: Vec<PublicKeyHex>, // PublicKey as hex

    /// Events which match these kinds
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[serde(default)]
    pub kinds: Vec<EventKind>,

    /// Events which refer to this naddr in an 'a' tag
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[serde(rename = "#a")]
    #[serde(default)]
    pub a: Vec<String>,

    /// Events which refer to this parameter in a 'd' tag
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[serde(rename = "#d")]
    #[serde(default)]
    pub d: Vec<String>,

    /// Events which refer to these other events in an 'e' tag
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[serde(rename = "#e")]
    #[serde(default)]
    pub e: Vec<IdHex>,

    /// Events which refer to this geohash in a 'g' tag
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[serde(rename = "#g")]
    #[serde(default)]
    pub g: Vec<String>,

    /// Events which refer to these public keys in a 'p' tag
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[serde(rename = "#p")]
    #[serde(default)]
    pub p: Vec<PublicKeyHex>,

    /// Events which refer to this URL reference in an 'r' tag
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[serde(rename = "#r")]
    #[serde(default)]
    pub r: Vec<String>,

    /// Events which refer to this hashtag in a 't' tag
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[serde(rename = "#t")]
    #[serde(default)]
    pub t: Vec<String>,

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

impl Filter {
    /// Create a new Filter object
    pub fn new() -> Filter {
        Default::default()
    }

    /// Add an Id to the filter.
    pub fn add_id(&mut self, id_hex: &IdHex) {
        if !self.ids.contains(id_hex) {
            self.ids.push(id_hex.to_owned());
        }
    }

    /// Delete an Id from the filter
    pub fn del_id(&mut self, id_hex: &IdHex) {
        if let Some(index) = self.ids.iter().position(|id| *id == *id_hex) {
            let _ = self.ids.swap_remove(index);
        }
    }

    /// Add a PublicKey to the filter
    pub fn add_author(&mut self, public_key_hex: &PublicKeyHex) {
        if !self.authors.contains(public_key_hex) {
            self.authors.push(public_key_hex.to_owned());
        }
    }

    /// Delete a PublicKey from the filter
    pub fn del_author(&mut self, public_key_hex: &PublicKeyHex) {
        if let Some(index) = self.authors.iter().position(|pk| *pk == *public_key_hex) {
            let _ = self.authors.swap_remove(index);
        }
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
            ids: vec![IdHex::try_from_str(
                "3ab7b776cb547707a7497f209be799710ce7eb0801e13fd3c4e7b9261ac29084",
            )
            .unwrap()],
            authors: vec![],
            kinds: vec![EventKind::TextNote, EventKind::Metadata],
            e: vec![IdHex::mock()],
            p: vec![PublicKeyHex::try_from_str(
                "221115830ced1ca94352002485fcc7a75dcfe30d1b07f5f6fbe9c0407cfa59a1",
            )
            .unwrap()],
            since: Some(Unixtime(1668572286)),
            ..Default::default()
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    test_serde! {Filter, test_filters_serde}

    #[test]
    fn test_filter_mock() {
        assert_eq!(
            &serde_json::to_string(&Filter::mock()).unwrap(),
            r##"{"ids":["3ab7b776cb547707a7497f209be799710ce7eb0801e13fd3c4e7b9261ac29084"],"kinds":[1,0],"#e":["5df64b33303d62afc799bdc36d178c07b2e1f0d824f31b7dc812219440affab6"],"#p":["221115830ced1ca94352002485fcc7a75dcfe30d1b07f5f6fbe9c0407cfa59a1"],"since":1668572286}"##
        );
    }

    #[test]
    fn test_add_remove_id() {
        let mock = IdHex::mock();

        let mut filters: Filter = Filter::new();

        filters.add_id(&mock);
        assert_eq!(filters.ids.len(), 1);
        filters.add_id(&mock); // overwrites
        assert_eq!(filters.ids.len(), 1);
        filters.del_id(&mock);
        assert!(filters.ids.is_empty());
    }

    // add_remove_author would be very similar to the above
}
