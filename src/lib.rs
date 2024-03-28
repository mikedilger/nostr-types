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

#[cfg(test)]
macro_rules! test_serde {
    ($t:ty, $fnname:ident) => {
        #[test]
        fn $fnname() {
            let a = <$t>::mock();
            let x = serde_json::to_string(&a).unwrap();
            println!("{}", x);
            let b = serde_json::from_str(&x).unwrap();
            assert_eq!(a, b);
        }
    };
}

mod types;
pub use types::{
    find_nostr_bech32_pos, find_nostr_url_pos, ClientMessage, ContentEncryptionAlgorithm,
    ContentSegment, DelegationConditions, EncryptedPrivateKey, Event, EventAddr, EventDelegation,
    EventKind, EventKindIterator, EventKindOrRange, EventPointer, EventReference, Fee, Filter, Id,
    IdHex, Identity, KeySecurity, KeySigner, Metadata, MilliSatoshi, Nip05, NostrBech32, NostrUrl,
    PayRequestData, PreEvent, PrivateKey, Profile, PublicKey, PublicKeyHex, RelayFees,
    RelayInformationDocument, RelayLimitation, RelayList, RelayMessage, RelayRetention, RelayUrl,
    RelayUsage, Rumor, ShatteredContent, Signature, SignatureHex, Signer, SimpleRelayList,
    SimpleRelayUsage, Span, SubscriptionId, Tag, UncheckedUrl, Unixtime, Url, XOnlyPublicKey,
    ZapData,
};

mod versioned;
pub use versioned::{
    ClientMessageV1, ClientMessageV2, ClientMessageV3, EventV1, EventV2, EventV3, FeeV1,
    MetadataV1, Nip05V1, PreEventV1, PreEventV2, PreEventV3, RelayFeesV1,
    RelayInformationDocumentV1, RelayInformationDocumentV2, RelayLimitationV1, RelayLimitationV2,
    RelayMessageV1, RelayMessageV2, RelayMessageV3, RelayMessageV4, RelayRetentionV1, RumorV1,
    RumorV2, RumorV3, TagV1, TagV2, TagV3, Why,
};

#[inline]
pub(crate) fn get_leading_zero_bits(bytes: &[u8]) -> u8 {
    let mut res = 0_u8;
    for b in bytes {
        if *b == 0 {
            res += 8;
        } else {
            res += b.leading_zeros() as u8;
            return res;
        }
    }
    res
}

trait IntoVec<T> {
    fn into_vec(self) -> Vec<T>;
}

impl<T> IntoVec<T> for Option<T> {
    fn into_vec(self) -> Vec<T> {
        match self {
            None => vec![],
            Some(t) => vec![t],
        }
    }
}
