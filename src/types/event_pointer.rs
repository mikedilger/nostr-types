use super::{Id, UncheckedUrl};
use crate::Error;
use bech32::{FromBase32, ToBase32};
use serde::{Deserialize, Serialize};

/// An event id along with some relays in which that event may be found.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct EventPointer {
    /// Event id
    pub id: Id,

    /// Some of the relays where this could be in
    pub relays: Vec<UncheckedUrl>,
}

impl EventPointer {
    /// Export as a bech32 encoded string ("nevent")
    pub fn as_bech32_string(&self) -> String {
        // Compose
        let mut tlv: Vec<u8> = Vec::new();

        // Push Public Key
        tlv.push(0); // the special value, in this case the public key
        tlv.push(32); // the length of the value (always 32 for public key)
        tlv.extend(self.id.0);

        // Push relays
        for relay in &self.relays {
            tlv.push(1); // type 'relay'
            tlv.push(relay.0.len() as u8); // the length of the string
            tlv.extend(relay.0.as_bytes());
        }

        bech32::encode("nevent", tlv.to_base32(), bech32::Variant::Bech32).unwrap()
    }

    /// Import from a bech32 encoded string ("nevent")
    pub fn try_from_bech32_string(s: &str) -> Result<EventPointer, Error> {
        let data = bech32::decode(s)?;
        if data.0 != "nevent" {
            Err(Error::WrongBech32("nevent".to_string(), data.0))
        } else {
            let mut relays: Vec<UncheckedUrl> = Vec::new();
            let mut id: Option<Id> = None;
            let tlv = Vec::<u8>::from_base32(&data.1)?;
            let mut pos = 0;
            loop {
                // we need at least 2 more characters for anything meaningful
                if pos > tlv.len() - 2 {
                    break;
                }
                let ty = tlv[pos];
                let len = tlv[pos + 1] as usize;
                pos += 2;
                if pos + len > tlv.len() {
                    return Err(Error::InvalidProfile);
                }
                match ty {
                    0 => {
                        // special, 32 bytes of id
                        if len != 32 {
                            return Err(Error::InvalidEventPointer);
                        }
                        id = Some(Id(tlv[pos..pos + len]
                            .try_into()
                            .map_err(|_| Error::WrongLengthHexString)?));
                    }
                    1 => {
                        // relay
                        let relay_bytes = &tlv[pos..pos + len];
                        let relay_str = std::str::from_utf8(relay_bytes)?;
                        let relay = UncheckedUrl::from_str(relay_str);
                        relays.push(relay);
                    }
                    _ => {} // unhandled type for nprofile
                }
                pos += len;
            }
            if let Some(id) = id {
                Ok(EventPointer { id, relays })
            } else {
                Err(Error::InvalidEventPointer)
            }
        }
    }

    // Mock data for testing
    #[allow(dead_code)]
    pub(crate) fn mock() -> EventPointer {
        let id = Id::try_from_hex_string(
            "b0635d6a9851d3aed0cd6c495b282167acf761729078d975fc341b22650b07b9",
        )
        .unwrap();

        EventPointer {
            id,
            relays: vec![
                UncheckedUrl::from_str("wss://relay.example.com"),
                UncheckedUrl::from_str("wss://relay2.example.com"),
            ],
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    test_serde! {EventPointer, test_event_pointer_serde}

    #[test]
    fn test_profile_bech32() {
        let bech32 = EventPointer::mock().as_bech32_string();
        println!("{bech32}");
        assert_eq!(
            EventPointer::mock(),
            EventPointer::try_from_bech32_string(&bech32).unwrap()
        );
    }

    #[test]
    fn test_nip19_example() {
        let event_pointer = EventPointer {
            id: Id::try_from_hex_string(
                "3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d",
            )
            .unwrap(),
            relays: vec![
                UncheckedUrl::from_str("wss://r.x.com"),
                UncheckedUrl::from_str("wss://djbas.sadkb.com"),
            ],
        };

        let bech32 = "nevent1qqsrhuxx8l9ex335q7he0f09aej04zpazpl0ne2cgukyawd24mayt8gpp4mhxue69uhhytnc9e3k7mgpz4mhxue69uhkg6nzv9ejuumpv34kytnrdaks343fay";

        // Try converting profile to bech32
        assert_eq!(event_pointer.as_bech32_string(), bech32);

        // Try converting bech32 to profile
        assert_eq!(
            event_pointer,
            EventPointer::try_from_bech32_string(bech32).unwrap()
        );

        // Try this one that used to fail
        let bech32 =
            "nevent1qqstxx3lk7zqfyn8cyyptvujfxq9w6mad4205x54772tdkmyqaay9scrqsqqqpp8x4vwhf";
        let _ = EventPointer::try_from_bech32_string(bech32).unwrap();
        // it won't be equal, but should have the basics and should not error.
    }
}
