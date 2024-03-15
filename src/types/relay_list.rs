use crate::types::{Event, RelayUrl, Tag};
use std::collections::HashMap;

/// Relay Usage
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum RelayUsage {
    /// The relay is used as an inbox (called 'read' in kind-10002)
    Inbox,

    /// The relay is used as an outbox (called 'write' in kind-10002)
    Outbox,

    /// The relay is used both as an inbox and an outbox
    #[default]
    Both,
}

impl RelayUsage {
    /// A string marker used in a kind-10002 RelayList event for the variant
    pub fn marker(&self) -> Option<&'static str> {
        match self {
            RelayUsage::Inbox => Some("read"),
            RelayUsage::Outbox => Some("write"),
            RelayUsage::Both => None,
        }
    }
}

/// A relay list, indicating usage for each relay, which can be used to
/// represent the data found in a kind 10002 RelayListMetadata event.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RelayList(pub HashMap<RelayUrl, RelayUsage>);

impl RelayList {
    /// Parse a kind-10002 RelayList event into a RelayList
    ///
    /// This does not check the event kind, that is left up to the caller.
    pub fn from_event(event: &Event) -> RelayList {
        let mut relay_list: RelayList = Default::default();

        for tag in event.tags.iter() {
            if let Ok((uurl, optmarker)) = tag.parse_relay() {
                if let Ok(relay_url) = RelayUrl::try_from_unchecked_url(&uurl) {
                    if let Some(m) = optmarker {
                        match &*m.trim().to_lowercase() {
                            "read" => {
                                let _ = relay_list.0.insert(relay_url, RelayUsage::Inbox);
                            }
                            "write" => {
                                let _ = relay_list.0.insert(relay_url, RelayUsage::Outbox);
                            }
                            _ => {} // ignore unknown marker
                        }
                    } else {
                        let _ = relay_list.0.insert(relay_url, RelayUsage::Both);
                    }
                }
            }
        }

        relay_list
    }

    /// Create a `Vec<Tag>` appropriate for forming a kind-10002 RelayList event
    pub fn to_event_tags(&self) -> Vec<Tag> {
        let mut tags: Vec<Tag> = Vec::new();
        for (relay_url, usage) in self.0.iter() {
            tags.push(Tag::new_relay(
                relay_url.to_unchecked_url(),
                usage.marker().map(|s| s.to_owned()),
            ));
        }
        tags
    }
}
