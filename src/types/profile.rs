use super::{PublicKey, Url};
use crate::Error;
use bech32::{FromBase32, ToBase32};
use serde::{Deserialize, Serialize};

/// A person's profile on nostr which consists of the data needed in order to follow someone.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Profile {
    /// Their public key
    pub pubkey: PublicKey,

    /// Some of the relays they post to (when the profile was created)
    pub relays: Vec<Url>,
}

impl Profile {
    /// Export as a bech32 encoded string ("nprofile")
    pub fn try_as_bech32_string(&self) -> Result<String, Error> {
        // Compose
        let mut tlv: Vec<u8> = Vec::new();

        // Push Public Key
        tlv.push(0); // the special value, in this case the public key
        tlv.push(32); // the length of the value (always 32 for public key)
        tlv.extend(self.pubkey.0.to_bytes());

        // Push relays
        for relay in &self.relays {
            tlv.push(1); // type 'relay'
            tlv.push(relay.len() as u8); // the length of the string
            tlv.extend(relay.as_bytes());
        }

        Ok(bech32::encode(
            "nprofile",
            tlv.to_base32(),
            bech32::Variant::Bech32,
        )?)
    }

    /// Import from a bech32 encoded string ("nprofile")
    pub fn try_from_bech32_string(s: &str) -> Result<Profile, Error> {
        let data = bech32::decode(s)?;
        if data.0 != "nprofile" {
            Err(Error::WrongBech32("nprofile".to_string(), data.0))
        } else {
            let tlv = Vec::<u8>::from_base32(&data.1)?;
            if tlv[0] != 0 || tlv[1] != 32 {
                return Err(Error::InvalidProfile);
            }
            let pubkey = PublicKey::from_bytes(&tlv[2..2 + 32])?;
            let mut relays: Vec<Url> = Vec::new();
            let mut pos = 2 + 32;
            while tlv.len() >= pos + 2 {
                let typ = tlv[pos];
                let len = tlv[pos + 1];
                pos += 2;
                if typ != 1 {
                    return Err(Error::InvalidProfile);
                }
                if tlv.len() < pos + len as usize {
                    return Err(Error::InvalidProfile);
                }
                let relay_bytes = &tlv[pos..pos + (len as usize)];
                let relay_str = std::str::from_utf8(relay_bytes)?;
                let relay = Url::new(relay_str);
                if !relay.is_valid_relay_url() {
                    return Err(Error::InvalidProfile);
                }
                relays.push(relay);
                pos += len as usize;
            }
            Ok(Profile { pubkey, relays })
        }
    }

    // Mock data for testing
    #[allow(dead_code)]
    pub(crate) fn mock() -> Profile {
        let pubkey = PublicKey::try_from_hex_string(
            "b0635d6a9851d3aed0cd6c495b282167acf761729078d975fc341b22650b07b9",
        )
        .unwrap();

        Profile {
            pubkey,
            relays: vec![
                Url::new("wss://relay.example.com"),
                Url::new("wss://relay2.example.com"),
            ],
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    test_serde! {Profile, test_profile_serde}

    #[test]
    fn test_profile_bech32() {
        let bech32 = Profile::mock().try_as_bech32_string().unwrap();
        println!("{}", bech32);
        assert_eq!(
            Profile::mock(),
            Profile::try_from_bech32_string(&bech32).unwrap()
        );
    }

    #[test]
    fn test_nip19_example() {
        let profile = Profile {
            pubkey: PublicKey::try_from_hex_string(
                "3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d",
            )
            .unwrap(),
            relays: vec![Url::new("wss://r.x.com"), Url::new("wss://djbas.sadkb.com")],
        };

        let bech32 = "nprofile1qqsrhuxx8l9ex335q7he0f09aej04zpazpl0ne2cgukyawd24mayt8gpp4mhxue69uhhytnc9e3k7mgpz4mhxue69uhkg6nzv9ejuumpv34kytnrdaksjlyr9p";

        // Try converting profile to bech32
        assert_eq!(profile.try_as_bech32_string().unwrap(), bech32);

        // Try converting bech32 to profile
        assert_eq!(profile, Profile::try_from_bech32_string(bech32).unwrap());
    }
}
