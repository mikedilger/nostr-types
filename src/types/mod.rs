#[cfg(test)]
macro_rules! test_serde {
    ($t:ty, $fnname:ident) => {
        #[test]
        fn $fnname() {
            let a = <$t>::mock();
            let x = serde_json::to_string(&a).unwrap();
            let b = serde_json::from_str(&x).unwrap();
            assert_eq!(a, b);
        }
    };
}

mod client_message;
pub use client_message::ClientMessage;

mod event;
pub use event::{Event, PreEvent};

mod event_kind;
pub use event_kind::EventKind;

mod filter;
pub use filter::Filters;

mod id;
pub use id::Id;

mod metadata;
pub use metadata::Metadata;

mod private_key;
pub use private_key::PrivateKey;

mod public_key;
pub use public_key::PublicKey;

mod relay_message;
pub use relay_message::RelayMessage;

mod signature;
pub use signature::Signature;

mod subscription_id;
pub use subscription_id::SubscriptionId;

mod tag;
pub use tag::Tag;

mod unixtime;
pub use unixtime::Unixtime;

mod url;
pub use url::Url;
