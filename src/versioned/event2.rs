use super::TagV2;
use crate::types::{
    EventAddr, EventKind, EventReference, Id, KeySigner, MilliSatoshi, NostrBech32, NostrUrl,
    PrivateKey, PublicKey, PublicKeyHex, RelayUrl, Signature, Signer, Unixtime, ZapData,
};
use crate::{Error, IntoVec};
use lightning_invoice::Bolt11Invoice;
#[cfg(feature = "speedy")]
use regex::Regex;
use serde::{Deserialize, Serialize};
#[cfg(feature = "speedy")]
use speedy::{Readable, Writable};
use std::str::FromStr;

/// The main event type
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "speedy", derive(Readable, Writable))]
pub struct EventV2 {
    /// The Id of the event, generated as a SHA256 of the inner event data
    pub id: Id,

    /// The public key of the actor who created the event
    pub pubkey: PublicKey,

    /// The (unverified) time at which the event was created
    pub created_at: Unixtime,

    /// The kind of event
    pub kind: EventKind,

    /// The signature of the event, which cryptographically verifies that the holder of
    /// the PrivateKey matching the event's PublicKey generated (or authorized) this event.
    /// The signature is taken over the id field only, but the id field is taken over
    /// the rest of the event data.
    pub sig: Signature,

    /// The content of the event
    pub content: String,

    /// A set of tags that apply to the event
    pub tags: Vec<TagV2>,
}

macro_rules! serialize_inner_event {
    ($pubkey:expr, $created_at:expr, $kind:expr, $tags:expr,
     $content:expr) => {{
        format!(
            "[0,{},{},{},{},{}]",
            serde_json::to_string($pubkey)?,
            serde_json::to_string($created_at)?,
            serde_json::to_string($kind)?,
            serde_json::to_string($tags)?,
            serde_json::to_string($content)?
        )
    }};
}

/// Data used to construct an event
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "speedy", derive(Readable, Writable))]
pub struct PreEventV2 {
    /// The public key of the actor who is creating the event
    pub pubkey: PublicKey,
    /// The time at which the event was created
    pub created_at: Unixtime,
    /// The kind of event
    pub kind: EventKind,
    /// A set of tags that apply to the event
    pub tags: Vec<TagV2>,
    /// The content of the event
    pub content: String,
}

impl PreEventV2 {
    /// Generate an ID from this PreEvent for use in an Event or a Rumor
    pub fn hash(&self) -> Result<Id, Error> {
        use secp256k1::hashes::Hash;

        let serialized: String = serialize_inner_event!(
            &self.pubkey,
            &self.created_at,
            &self.kind,
            &self.tags,
            &self.content
        );

        // Hash
        let hash = secp256k1::hashes::sha256::Hash::hash(serialized.as_bytes());
        let id: [u8; 32] = hash.to_byte_array();
        Ok(Id(id))
    }
}

/// A Rumor is an Event without a signature
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "speedy", derive(Readable, Writable))]
pub struct RumorV2 {
    /// The Id of the event, generated as a SHA256 of the inner event data
    pub id: Id,

    /// The public key of the actor who created the event
    pub pubkey: PublicKey,

    /// The (unverified) time at which the event was created
    pub created_at: Unixtime,

    /// The kind of event
    pub kind: EventKind,

    /// The content of the event
    pub content: String,

    /// A set of tags that apply to the event
    pub tags: Vec<TagV2>,
}

impl RumorV2 {
    /// Create a new rumor
    pub fn new(input: PreEventV2) -> Result<RumorV2, Error> {
        // Generate Id
        let id = input.hash()?;

        Ok(RumorV2 {
            id,
            pubkey: input.pubkey,
            created_at: input.created_at,
            kind: input.kind,
            tags: input.tags,
            content: input.content,
        })
    }

    /// Turn into an Event (the signature will be all zeroes)
    pub fn into_event_with_bad_signature(self) -> EventV2 {
        EventV2 {
            id: self.id,
            pubkey: self.pubkey,
            created_at: self.created_at,
            kind: self.kind,
            sig: Signature::zeroes(),
            content: self.content,
            tags: self.tags,
        }
    }
}

impl EventV2 {
    /// Check the validity of an event. This is useful if you deserialize an event
    /// from the network. If you create an event using new() it should already be
    /// trustworthy.
    pub fn verify(&self, maxtime: Option<Unixtime>) -> Result<(), Error> {
        use secp256k1::hashes::Hash;

        let serialized: String = serialize_inner_event!(
            &self.pubkey,
            &self.created_at,
            &self.kind,
            &self.tags,
            &self.content
        );

        // Verify the signature
        self.pubkey.verify(serialized.as_bytes(), &self.sig)?;

        // Also verify the ID is the SHA256
        // (the above verify function also does it internally,
        //  so there is room for improvement here)
        let hash = secp256k1::hashes::sha256::Hash::hash(serialized.as_bytes());
        let id: [u8; 32] = hash.to_byte_array();

        // Optional verify that the message was in the past
        if let Some(mt) = maxtime {
            if self.created_at > mt {
                return Err(Error::EventInFuture);
            }
        }

        if id != self.id.0 {
            Err(Error::HashMismatch)
        } else {
            Ok(())
        }
    }

    /// Mock data for testing
    #[allow(dead_code)]
    pub(crate) fn mock() -> EventV2 {
        let signer = {
            let private_key = PrivateKey::mock();
            KeySigner::from_private_key(private_key, "", 1).unwrap()
        };
        let public_key = signer.public_key();
        let pre = PreEventV2 {
            pubkey: public_key,
            created_at: Unixtime::mock(),
            kind: EventKind::mock(),
            tags: vec![TagV2::mock(), TagV2::mock()],
            content: "This is a test".to_string(),
        };
        signer.sign_event2(pre).unwrap()
    }

    /// Get the k-tag kind, if any
    pub fn k_tag_kind(&self) -> Option<EventKind> {
        for tag in self.tags.iter() {
            if let TagV2::Kind { kind, .. } = tag {
                return Some(*kind);
            }
        }
        None
    }

    /// If the event refers to people by tag, get all the PublicKeys it refers to
    /// along with recommended relay URL and petname for each
    pub fn people(&self) -> Vec<(PublicKeyHex, Option<RelayUrl>, Option<String>)> {
        let mut output: Vec<(PublicKeyHex, Option<RelayUrl>, Option<String>)> = Vec::new();
        // All 'p' tags
        for tag in self.tags.iter() {
            if let TagV2::Pubkey {
                pubkey,
                recommended_relay_url,
                petname,
                ..
            } = tag
            {
                output.push((
                    pubkey.to_owned(),
                    recommended_relay_url
                        .as_ref()
                        .and_then(|rru| RelayUrl::try_from_unchecked_url(rru).ok()),
                    petname.to_owned(),
                ));
            }
        }

        output
    }

    /// If the pubkey is tagged in the event
    pub fn is_tagged(&self, pubkey: &PublicKey) -> bool {
        let pkh: PublicKeyHex = pubkey.into();

        for tag in self.tags.iter() {
            if let TagV2::Pubkey { pubkey, .. } = tag {
                if *pubkey == pkh {
                    return true;
                }
            }
        }

        false
    }

    /// If the event refers to people within the contents, get all the PublicKeys it refers
    /// to within the contents.
    pub fn people_referenced_in_content(&self) -> Vec<PublicKey> {
        let mut output = Vec::new();
        for nurl in NostrUrl::find_all_in_string(&self.content).drain(..) {
            if let NostrBech32::Pubkey(pk) = nurl.0 {
                output.push(pk);
            }
            if let NostrBech32::Profile(prof) = nurl.0 {
                output.push(prof.pubkey);
            }
        }
        output
    }

    /// All events IDs that this event refers to, whether root, reply, mention, or otherwise
    /// along with optional recommended relay URLs
    pub fn referred_events(&self) -> Vec<EventReference> {
        let mut output: Vec<EventReference> = Vec::new();

        // Collect every 'e' tag and 'a' tag
        for tag in self.tags.iter() {
            if let TagV2::Event {
                id,
                recommended_relay_url,
                marker,
                ..
            } = tag
            {
                output.push(EventReference::Id {
                    id: *id,
                    author: None,
                    relays: recommended_relay_url
                        .as_ref()
                        .and_then(|rru| RelayUrl::try_from_unchecked_url(rru).ok())
                        .into_vec(),
                    marker: marker.clone(),
                });
            } else if let TagV2::Address {
                kind,
                pubkey,
                d,
                relay_url: Some(rurl),
                ..
            } = tag
            {
                if let Ok(pk) = PublicKey::try_from_hex_string(pubkey.as_str(), true) {
                    output.push(EventReference::Addr(EventAddr {
                        d: d.to_string(),
                        relays: vec![rurl.clone()],
                        kind: *kind,
                        author: pk,
                    }));
                }
            }
        }

        output
    }

    /// Get a reference to another event that this event replies to.
    /// An event can only reply to one other event via 'e' or 'a' tag from a feed-displayable
    /// event that is not a Repost.
    pub fn replies_to(&self) -> Option<EventReference> {
        if !self.kind.is_feed_displayable() {
            return None;
        }

        // Repost 'e' and 'a' tags are always considered mentions, not replies.
        if self.kind == EventKind::Repost || self.kind == EventKind::GenericRepost {
            return None;
        }

        // If there are no 'e' tags nor 'a' tags, then none
        let num_event_ref_tags = self
            .tags
            .iter()
            .filter(|e| matches!(e, TagV2::Event { .. }) || matches!(e, TagV2::Address { .. }))
            .count();
        if num_event_ref_tags == 0 {
            return None;
        }

        // look for an 'e' tag with marker 'reply'
        for tag in self.tags.iter() {
            if let TagV2::Event {
                id,
                recommended_relay_url,
                marker,
                ..
            } = tag
            {
                if marker.is_some() && marker.as_deref().unwrap() == "reply" {
                    return Some(EventReference::Id {
                        id: *id,
                        author: None,
                        relays: recommended_relay_url
                            .as_ref()
                            .and_then(|rru| RelayUrl::try_from_unchecked_url(rru).ok())
                            .into_vec(),
                        marker: marker.clone(),
                    });
                }
            }
        }

        // look for an 'e' tag with marker 'root'
        for tag in self.tags.iter() {
            if let TagV2::Event {
                id,
                recommended_relay_url,
                marker,
                ..
            } = tag
            {
                if marker.is_some() && marker.as_deref().unwrap() == "root" {
                    return Some(EventReference::Id {
                        id: *id,
                        author: None,
                        relays: recommended_relay_url
                            .as_ref()
                            .and_then(|rru| RelayUrl::try_from_unchecked_url(rru).ok())
                            .into_vec(),
                        marker: marker.to_owned(),
                    });
                }
            }
        }

        // Use the last unmarked 'e' tag or any 'a' tag
        if let Some(tag) = self.tags.iter().rev().find(|t| {
            matches!(t, TagV2::Event { marker: None, .. })
                || matches!(t, TagV2::Address { marker: None, .. })
        }) {
            if let TagV2::Event {
                id,
                recommended_relay_url,
                marker,
                ..
            } = tag
            {
                return Some(EventReference::Id {
                    id: *id,
                    author: None,
                    relays: recommended_relay_url
                        .as_ref()
                        .and_then(|rru| RelayUrl::try_from_unchecked_url(rru).ok())
                        .into_vec(),
                    marker: marker.clone(),
                });
            } else if let TagV2::Address {
                kind,
                pubkey,
                d,
                relay_url: Some(rurl),
                ..
            } = tag
            {
                if let Ok(pk) = PublicKey::try_from_hex_string(pubkey.as_str(), true) {
                    return Some(EventReference::Addr(EventAddr {
                        d: d.to_string(),
                        relays: vec![rurl.clone()],
                        kind: *kind,
                        author: pk,
                    }));
                }
            }
        }

        None
    }

    /// If this event replies to a thread, get that threads root event Id if
    /// available, along with an optional recommended_relay_url
    pub fn replies_to_root(&self) -> Option<EventReference> {
        if !self.kind.is_feed_displayable() {
            return None;
        }

        // look for an 'e' tag with marker 'root'
        for tag in self.tags.iter() {
            if let TagV2::Event {
                id,
                recommended_relay_url,
                marker,
                ..
            } = tag
            {
                if marker.is_some() && marker.as_deref().unwrap() == "root" {
                    return Some(EventReference::Id {
                        id: *id,
                        author: None,
                        relays: recommended_relay_url
                            .as_ref()
                            .and_then(|rru| RelayUrl::try_from_unchecked_url(rru).ok())
                            .into_vec(),
                        marker: marker.to_owned(),
                    });
                }
            }
        }

        // otherwise use the first unmarked 'e' tag or first 'a' tag
        // (even if there is only 1 'e' or 'a' tag which means it is both root and reply)
        if let Some(tag) = self.tags.iter().find(|t| {
            matches!(t, TagV2::Event { marker: None, .. })
                || matches!(t, TagV2::Address { marker: None, .. })
        }) {
            if let TagV2::Event {
                id,
                recommended_relay_url,
                marker,
                ..
            } = tag
            {
                return Some(EventReference::Id {
                    id: *id,
                    author: None,
                    relays: recommended_relay_url
                        .as_ref()
                        .and_then(|rru| RelayUrl::try_from_unchecked_url(rru).ok())
                        .into_vec(),
                    marker: marker.to_owned(),
                });
            } else if let TagV2::Address {
                kind,
                pubkey,
                d,
                relay_url: Some(rurl),
                ..
            } = tag
            {
                if let Ok(pk) = PublicKey::try_from_hex_string(pubkey.as_str(), true) {
                    return Some(EventReference::Addr(EventAddr {
                        d: d.to_string(),
                        relays: vec![rurl.clone()],
                        kind: *kind,
                        author: pk,
                    }));
                }
            }
        }

        None
    }

    /// If this event mentions others, get those other event Ids
    /// and optional recommended relay Urls
    pub fn mentions(&self) -> Vec<EventReference> {
        if !self.kind.is_feed_displayable() {
            return vec![];
        }

        let mut output: Vec<EventReference> = Vec::new();

        // For kind=6 and kind=16, all 'e' and 'a' tags are mentions
        if self.kind == EventKind::Repost || self.kind == EventKind::GenericRepost {
            for tag in self.tags.iter() {
                if let TagV2::Event {
                    id,
                    recommended_relay_url,
                    marker,
                    ..
                } = tag
                {
                    output.push(EventReference::Id {
                        id: *id,
                        author: None,
                        relays: recommended_relay_url
                            .as_ref()
                            .and_then(|rru| RelayUrl::try_from_unchecked_url(rru).ok())
                            .into_vec(),
                        marker: marker.clone(),
                    });
                } else if let TagV2::Address {
                    kind,
                    pubkey,
                    d,
                    relay_url: Some(rurl),
                    marker: _,
                    trailing: _,
                } = tag
                {
                    if let Ok(pk) = PublicKey::try_from_hex_string(pubkey.as_str(), true) {
                        output.push(EventReference::Addr(EventAddr {
                            d: d.to_string(),
                            relays: vec![rurl.clone()],
                            kind: *kind,
                            author: pk,
                        }));
                    }
                }
            }

            return output;
        }

        // Look for nostr links within the content

        // Collect every 'e' tag marked as 'mention'
        for tag in self.tags.iter() {
            if let TagV2::Event {
                id,
                recommended_relay_url,
                marker,
                ..
            } = tag
            {
                if marker.is_some() && marker.as_deref().unwrap() == "mention" {
                    output.push(EventReference::Id {
                        id: *id,
                        author: None,
                        relays: recommended_relay_url
                            .as_ref()
                            .and_then(|rru| RelayUrl::try_from_unchecked_url(rru).ok())
                            .into_vec(),
                        marker: marker.clone(),
                    });
                }
            }
        }

        // Collect every unmarked 'e' or 'a' tag that is not the first (root) or the last (reply)
        let e_tags: Vec<&TagV2> = self
            .tags
            .iter()
            .filter(|e| {
                matches!(e, TagV2::Event { marker: None, .. })
                    || matches!(e, TagV2::Address { marker: None, .. })
            })
            .collect();
        if e_tags.len() > 2 {
            // mentions are everything other than first and last
            for tag in &e_tags[1..e_tags.len() - 1] {
                if let TagV2::Event {
                    id,
                    recommended_relay_url,
                    marker,
                    ..
                } = tag
                {
                    output.push(EventReference::Id {
                        id: *id,
                        author: None,
                        relays: recommended_relay_url
                            .as_ref()
                            .and_then(|rru| RelayUrl::try_from_unchecked_url(rru).ok())
                            .into_vec(),
                        marker: marker.to_owned(),
                    });
                } else if let TagV2::Address {
                    kind,
                    pubkey,
                    d,
                    relay_url: Some(rurl),
                    ..
                } = tag
                {
                    if let Ok(pk) = PublicKey::try_from_hex_string(pubkey.as_str(), true) {
                        output.push(EventReference::Addr(EventAddr {
                            d: d.to_string(),
                            relays: vec![rurl.clone()],
                            kind: *kind,
                            author: pk,
                        }));
                    }
                }
            }
        }

        output
    }

    /// If this event reacts to another, get that other event's Id,
    /// the reaction content, and an optional Recommended relay Url
    pub fn reacts_to(&self) -> Option<(Id, String, Option<RelayUrl>)> {
        if self.kind != EventKind::Reaction {
            return None;
        }

        // The last 'e' tag is it
        if let Some(TagV2::Event {
            id,
            recommended_relay_url,
            ..
        }) = self
            .tags
            .iter()
            .rev()
            .find(|t| matches!(t, TagV2::Event { .. }))
        {
            return Some((
                *id,
                self.content.clone(),
                recommended_relay_url
                    .as_ref()
                    .and_then(|rru| RelayUrl::try_from_unchecked_url(rru).ok()),
            ));
        }

        None
    }

    /// If this event deletes others, get all the EventReferences of the events that it
    /// deletes along with the reason for the deletion
    pub fn deletes(&self) -> Option<(Vec<EventReference>, String)> {
        if self.kind != EventKind::EventDeletion {
            return None;
        }

        let mut erefs: Vec<EventReference> = Vec::new();

        for tag in self.tags.iter() {
            // All 'e' tags are deleted
            if let TagV2::Event { id, .. } = tag {
                erefs.push(EventReference::Id {
                    id: *id,
                    author: None,
                    relays: vec![],
                    marker: None,
                });
            }
            // All 'a' tag groups are deleted
            else if let TagV2::Address {
                kind,
                pubkey,
                d,
                relay_url,
                ..
            } = tag
            {
                if let Ok(pk) = PublicKey::try_from_hex_string(pubkey, false) {
                    let ea = EventAddr {
                        d: d.clone(),
                        relays: match relay_url {
                            Some(url) => vec![url.clone()],
                            None => vec![],
                        },
                        kind: *kind,
                        author: pk,
                    };
                    erefs.push(EventReference::Addr(ea));
                }
            }
        }

        if erefs.is_empty() {
            None
        } else {
            Some((erefs, self.content.clone()))
        }
    }

    /// Can this event be deleted by the given public key?
    pub fn delete_author_allowed(&self, by: PublicKey) -> bool {
        // Author can always delete
        if self.pubkey == by {
            return true;
        }

        if self.kind == EventKind::GiftWrap {
            for tag in self.tags.iter() {
                if let TagV2::Pubkey { pubkey, .. } = tag {
                    let pkh: PublicKeyHex = by.into();
                    return pkh == *pubkey;
                }
            }
        }

        false
    }

    /// If this event zaps another event, get data about that.
    ///
    /// That includes the Id, the amount, and the public key of the provider,
    /// all of which should be verified by the caller.
    ///
    /// Errors returned from this are not fatal, but may be useful for
    /// explaining to a user why a zap receipt is invalid.
    pub fn zaps(&self) -> Result<Option<ZapData>, Error> {
        if self.kind != EventKind::Zap {
            return Ok(None);
        }

        let mut zapped_id: Option<Id> = None;
        let mut zapped_amount: Option<MilliSatoshi> = None;
        let mut zapped_pubkey: Option<PublicKey> = None;

        for tag in self.tags.iter() {
            if let TagV2::Other { tag, data } = tag {
                // Find the bolt11 tag
                if tag != "bolt11" {
                    continue;
                }
                if data.is_empty() {
                    return Err(Error::ZapReceipt("missing bolt11 tag value".to_string()));
                }

                // Extract as an Invoice
                let result = Bolt11Invoice::from_str(&data[0]);
                if let Err(e) = result {
                    return Err(Error::ZapReceipt(format!("bolt11 failed to parse: {}", e)));
                }
                let invoice = result.unwrap();

                // Verify the signature
                if let Err(e) = invoice.check_signature() {
                    return Err(Error::ZapReceipt(format!(
                        "bolt11 signature check failed: {}",
                        e
                    )));
                }

                // Get the public key
                let secpk = match invoice.payee_pub_key() {
                    Some(pubkey) => pubkey.to_owned(),
                    None => invoice.recover_payee_pub_key(),
                };
                let (xonlypk, _) = secpk.x_only_public_key();
                let pubkeybytes = xonlypk.serialize();
                let pubkey = match PublicKey::from_bytes(&pubkeybytes, false) {
                    Ok(pubkey) => pubkey,
                    Err(e) => {
                        return Err(Error::ZapReceipt(format!("payee public key error: {}", e)))
                    }
                };
                zapped_pubkey = Some(pubkey);

                if let Some(u) = invoice.amount_milli_satoshis() {
                    zapped_amount = Some(MilliSatoshi(u));
                } else {
                    return Err(Error::ZapReceipt(
                        "Amount missing from zap receipt".to_string(),
                    ));
                }
            }
            if let TagV2::Event { id, .. } = tag {
                zapped_id = Some(*id);
            }
        }

        if zapped_id.is_none() {
            // This probably means a person was zapped, not a note. So not an error.
            return Ok(None);
        }
        if zapped_amount.is_none() {
            return Err(Error::ZapReceipt("Missing amount".to_string()));
        }
        if zapped_pubkey.is_none() {
            return Err(Error::ZapReceipt("Missing payee public key".to_string()));
        }

        Ok(Some(ZapData {
            id: zapped_id.unwrap(),
            amount: zapped_amount.unwrap(),
            pubkey: zapped_pubkey.unwrap(),
            provider_pubkey: self.pubkey,
        }))
    }

    /// If this event specifies the client that created it, return that client string
    pub fn client(&self) -> Option<String> {
        for tag in self.tags.iter() {
            if let TagV2::Other { tag, data } = tag {
                if tag == "client" && !data.is_empty() {
                    return Some(data[0].clone());
                }
            }
        }

        None
    }

    /// If this event specifies a subject, return that subject string
    pub fn subject(&self) -> Option<String> {
        for tag in self.tags.iter() {
            if let TagV2::Subject { subject, .. } = tag {
                return Some(subject.clone());
            }
        }

        None
    }

    /// If this event specifies a title, return that title string
    pub fn title(&self) -> Option<String> {
        for tag in self.tags.iter() {
            if let TagV2::Title { title, .. } = tag {
                return Some(title.clone());
            }
        }

        None
    }

    /// If this event specifies a summary, return that summary string
    pub fn summary(&self) -> Option<String> {
        for tag in self.tags.iter() {
            if let TagV2::Other { tag, data } = tag {
                if tag == "summary" && !data.is_empty() {
                    return Some(data[0].clone());
                }
            }
        }

        None
    }

    /// If this event specifies a content warning, return that subject string
    pub fn content_warning(&self) -> Option<String> {
        for tag in self.tags.iter() {
            if let TagV2::ContentWarning { warning, .. } = tag {
                return Some(warning.clone());
            }
        }

        None
    }

    /// If this is a parameterized event, get the parameter
    pub fn parameter(&self) -> Option<String> {
        if self.kind.is_parameterized_replaceable() {
            for tag in self.tags.iter() {
                if let TagV2::Identifier { d, .. } = tag {
                    return Some(d.to_owned());
                }
            }
            Some("".to_owned()) // implicit
        } else {
            None
        }
    }

    /// Return all the hashtags this event refers to
    pub fn hashtags(&self) -> Vec<String> {
        if !self.kind.is_feed_displayable() {
            return vec![];
        }

        let mut output: Vec<String> = Vec::new();

        for tag in self.tags.iter() {
            if let TagV2::Hashtag { hashtag, .. } = tag {
                output.push(hashtag.clone());
            }
        }

        output
    }

    /// Return all the URLs this event refers to
    pub fn urls(&self) -> Vec<RelayUrl> {
        if !self.kind.is_feed_displayable() {
            return vec![];
        }

        let mut output: Vec<RelayUrl> = Vec::new();

        for tag in self.tags.iter() {
            if let TagV2::Reference { url, .. } = tag {
                if let Ok(relay_url) = RelayUrl::try_from_unchecked_url(url) {
                    output.push(relay_url);
                }
            }
        }

        output
    }

    /// Get the proof-of-work count of leading bits
    pub fn pow(&self) -> u8 {
        // Count leading bits in the Id field
        let zeroes: u8 = crate::get_leading_zero_bits(&self.id.0);

        // Check that they meant it
        let mut target_zeroes: u8 = 0;
        for tag in self.tags.iter() {
            if let TagV2::Nonce { target, .. } = tag {
                if let Some(t) = target {
                    target_zeroes = t.parse::<u8>().unwrap_or(0);
                }
                break;
            }
        }

        zeroes.min(target_zeroes)
    }

    /// If the event came through a proxy, get the (Protocol, Id)
    pub fn proxy(&self) -> Option<(&str, &str)> {
        for t in self.tags.iter() {
            if let TagV2::Other { tag, data } = t {
                if tag == "proxy" && data.len() >= 2 {
                    return Some((&data[1], &data[0]));
                }
            }
        }
        None
    }
}

// Direct access into speedy-serialized bytes, to avoid alloc-deserialize just to peek
// at one of these fields
#[cfg(feature = "speedy")]
impl EventV2 {
    /// Read the ID of the event from a speedy encoding without decoding
    /// (zero allocation)
    ///
    /// Note this function is fragile, if the Event structure is reordered,
    /// or if speedy code changes, this will break.  Neither should happen.
    pub fn get_id_from_speedy_bytes(bytes: &[u8]) -> Option<Id> {
        if bytes.len() < 32 {
            None
        } else if let Ok(arr) = <[u8; 32]>::try_from(&bytes[0..32]) {
            Some(unsafe { std::mem::transmute(arr) })
        } else {
            None
        }
    }

    /// Read the pubkey of the event from a speedy encoding without decoding
    /// (close to zero allocation, VerifyingKey does stuff I didn't check)
    ///
    /// Note this function is fragile, if the Event structure is reordered,
    /// or if speedy code changes, this will break.  Neither should happen.
    pub fn get_pubkey_from_speedy_bytes(bytes: &[u8]) -> Option<PublicKey> {
        if bytes.len() < 64 {
            None
        } else {
            PublicKey::from_bytes(&bytes[32..64], false).ok()
        }
    }

    /// Read the created_at of the event from a speedy encoding without decoding
    /// (zero allocation)
    ///
    /// Note this function is fragile, if the Event structure is reordered,
    /// or if speedy code changes, this will break.  Neither should happen.
    pub fn get_created_at_from_speedy_bytes(bytes: &[u8]) -> Option<Unixtime> {
        if bytes.len() < 72 {
            None
        } else if let Ok(i) = i64::read_from_buffer(&bytes[64..72]) {
            Some(Unixtime(i))
        } else {
            None
        }
    }

    /// Read the kind of the event from a speedy encoding without decoding
    /// (zero allocation)
    ///
    /// Note this function is fragile, if the Event structure is reordered,
    /// or if speedy code changes, this will break.  Neither should happen.
    pub fn get_kind_from_speedy_bytes(bytes: &[u8]) -> Option<EventKind> {
        if bytes.len() < 76 {
            None
        } else if let Ok(u) = u32::read_from_buffer(&bytes[72..76]) {
            Some(u.into())
        } else {
            None
        }
    }

    // Read the sig of the event from a speedy encoding without decoding
    // (offset would be 76..140

    /// Read the content of the event from a speedy encoding without decoding
    /// (zero allocation)
    ///
    /// Note this function is fragile, if the Event structure is reordered,
    /// or if speedy code changes, this will break.  Neither should happen.
    pub fn get_content_from_speedy_bytes(bytes: &[u8]) -> Option<&str> {
        let len = u32::from_ne_bytes(bytes[140..140 + 4].try_into().unwrap());

        unsafe {
            Some(std::str::from_utf8_unchecked(
                &bytes[140 + 4..140 + 4 + len as usize],
            ))
        }
    }

    /// Check if any human-readable tag matches the Regex in the speedy encoding
    /// without decoding the whole thing (because our TagV2 representation is so complicated,
    /// we do deserialize the tags for now)
    ///
    /// Note this function is fragile, if the Event structure is reordered,
    /// or if speedy code changes, this will break.  Neither should happen.
    pub fn tag_search_in_speedy_bytes(bytes: &[u8], re: &Regex) -> Result<bool, Error> {
        if bytes.len() < 140 {
            return Ok(false);
        }

        // skip content
        let len = u32::from_ne_bytes(bytes[140..140 + 4].try_into().unwrap());
        let offset = 140 + 4 + len as usize;

        // Deserialize the tags
        let tags: Vec<TagV2> = Vec::<TagV2>::read_from_buffer(&bytes[offset..])?;

        // Search through them
        for tag in &tags {
            match tag {
                TagV2::ContentWarning { warning, .. } => {
                    if re.is_match(warning.as_ref()) {
                        return Ok(true);
                    }
                }
                TagV2::Hashtag { hashtag, .. } => {
                    if re.is_match(hashtag.as_ref()) {
                        return Ok(true);
                    }
                }
                TagV2::Subject { subject, .. } => {
                    if re.is_match(subject.as_ref()) {
                        return Ok(true);
                    }
                }
                TagV2::Title { title, .. } => {
                    if re.is_match(title.as_ref()) {
                        return Ok(true);
                    }
                }
                TagV2::Other { tag, data } => {
                    if tag == "summary" && !data.is_empty() && re.is_match(data[0].as_ref()) {
                        return Ok(true);
                    }
                }
                _ => {}
            }
        }

        Ok(false)
    }
}

impl From<EventV2> for RumorV2 {
    fn from(e: EventV2) -> RumorV2 {
        RumorV2 {
            id: e.id,
            pubkey: e.pubkey,
            created_at: e.created_at,
            kind: e.kind,
            content: e.content,
            tags: e.tags,
        }
    }
}

impl From<RumorV2> for PreEventV2 {
    fn from(r: RumorV2) -> PreEventV2 {
        PreEventV2 {
            pubkey: r.pubkey,
            created_at: r.created_at,
            kind: r.kind,
            content: r.content,
            tags: r.tags,
        }
    }
}

impl TryFrom<PreEventV2> for RumorV2 {
    type Error = Error;
    fn try_from(e: PreEventV2) -> Result<RumorV2, Error> {
        RumorV2::new(e)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::types::{Signer, UncheckedUrl};

    test_serde! {EventV2, test_event_serde}

    #[test]
    fn test_event_new_and_verify() {
        let signer = {
            let privkey = PrivateKey::mock();
            KeySigner::from_private_key(privkey, "", 1).unwrap()
        };
        let pubkey = signer.public_key();
        let preevent = PreEventV2 {
            pubkey,
            created_at: Unixtime::mock(),
            kind: EventKind::TextNote,
            tags: vec![TagV2::Event {
                id: Id::mock(),
                recommended_relay_url: Some(UncheckedUrl::mock()),
                marker: None,
                trailing: Vec::new(),
            }],
            content: "Hello World!".to_string(),
        };
        let mut event = signer.sign_event2(preevent).unwrap();
        assert!(event.verify(None).is_ok());

        // Now make sure it fails when the message has been modified
        event.content = "I'm changing this message".to_string();
        let result = event.verify(None);
        assert!(result.is_err());

        // Change it back
        event.content = "Hello World!".to_string();
        let result = event.verify(None);
        assert!(result.is_ok());

        // Tweak the id only
        event.id = Id([
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 31,
        ]);
        let result = event.verify(None);
        assert!(result.is_err());
    }

    #[test]
    fn test_realworld_event_with_naddr_tag() {
        let raw = r##"{"id":"7760408f6459b9546c3a4e70e3e56756421fba34526b7d460db3fcfd2f8817db","pubkey":"460c25e682fda7832b52d1f22d3d22b3176d972f60dcdc3212ed8c92ef85065c","created_at":1687616920,"kind":1,"tags":[["p","1bc70a0148b3f316da33fe3c89f23e3e71ac4ff998027ec712b905cd24f6a411","","mention"],["a","30311:1bc70a0148b3f316da33fe3c89f23e3e71ac4ff998027ec712b905cd24f6a411:1687612774","","mention"]],"content":"Watching Karnage's stream to see if I learn something about design. \n\nnostr:naddr1qq9rzd3cxumrzv3hxu6qygqmcu9qzj9n7vtd5vl78jyly037wxkyl7vcqflvwy4eqhxjfa4yzypsgqqqwens0qfplk","sig":"dbc5d05a24bfe990a1faaedfcb81a98940d86a105711dbdad9145d05b0ad0f46e3e24eaa3fc283818f27e057fe836a029fd9a68e7f1de06ff477493199d64064"}"##;
        let _: EventV2 = serde_json::from_str(&raw).unwrap();
    }

    #[cfg(feature = "speedy")]
    #[test]
    fn test_speedy_encoded_direct_field_access() {
        use speedy::Writable;

        let signer = {
            let privkey = PrivateKey::mock();
            KeySigner::from_private_key(privkey, "", 1).unwrap()
        };

        let preevent = PreEventV2 {
            pubkey: signer.public_key(),
            created_at: Unixtime(1680000012),
            kind: EventKind::TextNote,
            tags: vec![
                TagV2::Event {
                    id: Id::mock(),
                    recommended_relay_url: Some(UncheckedUrl::mock()),
                    marker: None,
                    trailing: Vec::new(),
                },
                TagV2::Hashtag {
                    hashtag: "foodstr".to_string(),
                    trailing: Vec::new(),
                },
            ],
            content: "Hello World!".to_string(),
        };
        let event = signer.sign_event2(preevent).unwrap();
        let bytes = event.write_to_vec().unwrap();

        let id = EventV2::get_id_from_speedy_bytes(&bytes).unwrap();
        assert_eq!(id, event.id);

        let pubkey = EventV2::get_pubkey_from_speedy_bytes(&bytes).unwrap();
        assert_eq!(pubkey, event.pubkey);

        let created_at = EventV2::get_created_at_from_speedy_bytes(&bytes).unwrap();
        assert_eq!(created_at, Unixtime(1680000012));

        let kind = EventV2::get_kind_from_speedy_bytes(&bytes).unwrap();
        assert_eq!(kind, event.kind);

        let content = EventV2::get_content_from_speedy_bytes(&bytes);
        assert_eq!(content, Some(&*event.content));

        let re = regex::Regex::new("foodstr").unwrap();
        let found_foodstr = EventV2::tag_search_in_speedy_bytes(&bytes, &re).unwrap();
        assert!(found_foodstr);

        // Print to work out encoding
        //   test like this to see printed data:
        //   cargo test --features=speedy test_speedy_encoded_direct_field_access -- --nocapture
        println!("EVENT BYTES: {:?}", bytes);
        println!("ID: {:?}", event.id.0);
        println!("PUBKEY: {:?}", event.pubkey.as_slice());
        println!("CREATED AT: {:?}", event.created_at.0.to_ne_bytes());
        let kind32: u32 = event.kind.into();
        println!("KIND: {:?}", kind32.to_ne_bytes());
        println!("SIG: {:?}", event.sig.0.as_ref());
        println!(
            "CONTENT: [len={:?}] {:?}",
            (event.content.as_bytes().len() as u32).to_ne_bytes(),
            event.content.as_bytes()
        );
        println!("TAGS: [len={:?}]", (event.tags.len() as u32).to_ne_bytes());
    }

    #[test]
    fn test_event_gift_wrap() {
        let signer1 = {
            let sec1 = PrivateKey::try_from_hex_string(
                "0000000000000000000000000000000000000000000000000000000000000001",
            )
            .unwrap();
            KeySigner::from_private_key(sec1, "", 1).unwrap()
        };

        let signer2 = {
            let sec2 = PrivateKey::try_from_hex_string(
                "0000000000000000000000000000000000000000000000000000000000000002",
            )
            .unwrap();
            KeySigner::from_private_key(sec2, "", 1).unwrap()
        };

        let pre = PreEventV2 {
            pubkey: signer1.public_key(),
            created_at: Unixtime(1692_000_000),
            kind: EventKind::TextNote,
            content: "Hey man, this rocks! Please reply for a test.".to_string(),
            tags: vec![],
        };

        let gift_wrap = signer1
            .giftwrap2(pre.clone(), signer2.public_key())
            .unwrap();
        let rumor = signer2.unwrap_giftwrap2(&gift_wrap).unwrap();
        let output_pre: PreEventV2 = rumor.into();

        assert_eq!(pre, output_pre);
    }
}
