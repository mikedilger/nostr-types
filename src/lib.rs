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
    unsafe_code,
    unreachable_pub,
    missing_docs,
    missing_copy_implementations
)]

mod error;
pub use error::Error;

mod types;
pub use types::{
    ClientMessage, EncryptedPrivateKey, Event, EventKind, Filter, Id, IdHex, KeySecurity, Metadata,
    Nip05, PreEvent, PrivateKey, PublicKey, PublicKeyHex, RelayInformationDocument, RelayMessage,
    Signature, SubscriptionId, Tag, Unixtime, Url,
};
