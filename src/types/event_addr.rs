use super::{EventKind, PublicKey, UncheckedUrl};
use crate::Error;
use bech32::{FromBase32, ToBase32};
use serde::{Deserialize, Serialize};
#[cfg(feature = "speedy")]
use speedy::{Readable, Writable};

/// An 'naddr': data to address a possibly parameterized replaceable event (d-tag, kind, author, and relays)
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[cfg_attr(feature = "speedy", derive(Readable, Writable))]
pub struct EventAddr {
    /// the 'd' tag of the Event, or an empty string if the kind is not parameterized
    pub d: String,

    /// Some of the relays where this could be found
    pub relays: Vec<UncheckedUrl>,

    /// Kind
    pub kind: EventKind,

    /// Author
    pub author: PublicKey,
}

impl EventAddr {
    /// Export as a bech32 encoded string ("naddr")
    pub fn as_bech32_string(&self) -> String {
        // Compose
        let mut tlv: Vec<u8> = Vec::new();

        // Push d tag
        tlv.push(0); // the special value, in this case the 'd' tag
        tlv.push(self.d.len() as u8); // the length of the d tag
        tlv.extend(self.d.as_bytes());

        // Push relays
        for relay in &self.relays {
            tlv.push(1); // type 'relay'
            tlv.push(relay.0.len() as u8); // the length of the string
            tlv.extend(relay.0.as_bytes());
        }

        // Push kind
        let kindnum: u32 = From::from(self.kind);
        let bytes = kindnum.to_be_bytes();
        tlv.push(3); // type 'kind'
        tlv.push(bytes.len() as u8); // '4'
        tlv.extend(bytes);

        // Push author
        tlv.push(2); // type 'author'
        tlv.push(32); // the length of the value (always 32 for public key)
        tlv.extend(self.author.as_bytes());

        bech32::encode("naddr", tlv.to_base32(), bech32::Variant::Bech32).unwrap()
    }

    /// Import from a bech32 encoded string ("naddr")
    pub fn try_from_bech32_string(s: &str) -> Result<EventAddr, Error> {
        let data = bech32::decode(s)?;
        if data.0 != "naddr" {
            Err(Error::WrongBech32("naddr".to_string(), data.0))
        } else {
            let mut maybe_d: Option<String> = None;
            let mut relays: Vec<UncheckedUrl> = Vec::new();
            let mut maybe_kind: Option<EventKind> = None;
            let mut maybe_author: Option<PublicKey> = None;

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
                let raw = &tlv[pos..pos + len];
                match ty {
                    0 => {
                        // special (bytes of d tag)
                        maybe_d = Some(std::str::from_utf8(raw)?.to_string());
                    }
                    1 => {
                        // relay
                        let relay_str = std::str::from_utf8(raw)?;
                        let relay = UncheckedUrl::from_str(relay_str);
                        relays.push(relay);
                    }
                    2 => {
                        // author
                        maybe_author = Some(PublicKey::from_bytes(raw, true)?);
                    }
                    3 => {
                        // kind
                        let kindnum = u32::from_be_bytes(
                            raw.try_into().map_err(|_| Error::WrongLengthKindBytes)?,
                        );
                        maybe_kind = Some(kindnum.into());
                    }
                    _ => {} // unhandled type for nprofile
                }
                pos += len;
            }

            match (maybe_d, maybe_kind, maybe_author) {
                (Some(d), Some(kind), Some(author)) => Ok(EventAddr {
                    d,
                    relays,
                    kind,
                    author,
                }),
                _ => Err(Error::InvalidEventAddr),
            }
        }
    }

    // Mock data for testing
    #[allow(dead_code)]
    pub(crate) fn mock() -> EventAddr {
        let d = "Test D Indentifier 1lkjf23".to_string();

        EventAddr {
            d,
            relays: vec![
                UncheckedUrl::from_str("wss://relay.example.com"),
                UncheckedUrl::from_str("wss://relay2.example.com"),
            ],
            kind: EventKind::LongFormContent,
            author: PublicKey::mock_deterministic(),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    test_serde! {EventAddr, test_event_addr_serde}

    #[test]
    fn test_profile_bech32() {
        let bech32 = EventAddr::mock().as_bech32_string();
        println!("{bech32}");
        assert_eq!(
            EventAddr::mock(),
            EventAddr::try_from_bech32_string(&bech32).unwrap()
        );
    }
}
