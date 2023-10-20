// Copyright 2015-2020 nostr-proto Developers
// Licensed under the MIT license <LICENSE-MIT or http://opensource.org/licenses/MIT>
// This file may not be copied, modified, or distributed except according to those terms.

//! This crate provides types for nostr protocol handling.

#![deny(
    missing_debug_implementations,
    trivial_casts,
    trivial_numeric_casts,
    unused_import_braces,
    unused_qualifications,
    unused_results,
    unused_lifetimes,
    unused_labels,
    unused_extern_crates,
    non_ascii_idents,
    keyword_idents,
    deprecated_in_future,
    unstable_features,
    single_use_lifetimes,
    //unsafe_code,
    unreachable_pub,
    missing_docs,
    missing_copy_implementations
)]
#![deny(clippy::string_slice)]

mod error;
pub use error::Error;

mod types;
pub use types::{
    find_nostr_bech32_pos, find_nostr_url_pos, ClientMessage, ContentEncryptionAlgorithm,
    ContentSegment, DelegationConditions, EncryptedPrivateKey, Event, EventAddr, EventDelegation,
    EventKind, EventKindIterator, EventKindOrRange, EventPointer, Fee, Filter, Id, IdHex,
    KeySecurity, Metadata, MilliSatoshi, Nip05, NostrBech32, NostrUrl, PayRequestData, PreEvent,
    PrivateKey, Profile, PublicKey, PublicKeyHex, RelayFees, RelayInformationDocument,
    RelayLimitation, RelayMessage, RelayRetention, RelayUrl, Rumor, ShatteredContent, Signature,
    SignatureHex, SimpleRelayList, SimpleRelayUsage, Span, SubscriptionId, Tag, UncheckedUrl,
    Unixtime, Url, XOnlyPublicKey, ZapData,
};
