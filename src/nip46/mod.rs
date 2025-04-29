use crate::{
    client, ContentEncryptionAlgorithm, EncryptedPrivateKey, Error, EventKind, Filter, Id,
    KeySecurity, KeySigner, PrivateKey, PublicKey, RelayUrl, Signature, Signer,
};
use async_trait::async_trait;
use serde::de::Error as DeError;
use serde::de::{Deserialize, Deserializer, SeqAccess, Visitor};
use serde::ser::{Serialize, SerializeSeq, Serializer};
use std::fmt;
use std::sync::Arc;
use std::time::Duration;

mod request;
pub use request::Nip46Request;

mod response;
pub use response::Nip46Response;

mod params;
pub use params::Nip46ConnectionParameters;

/// This allows us to constrain BunkerClient type to four different subtypes using
/// typestates
pub trait BunkerClientState {}

/// This is a NIP-46 Bunker client in one of four different states
#[derive(Debug, PartialEq, Eq)]
pub struct BunkerClient<S: BunkerClientState> {
    /// The pubkey of the bunker
    pub remote_signer_pubkey: PublicKey,

    /// The relay the bunker is listening at
    pub relay_url: RelayUrl,

    /// The connect secret
    pub connect_secret: Option<String>,

    /// Our local identity
    pub epk: EncryptedPrivateKey,

    /// State specific data
    state_data: S,
}

/// A `BunkerClient` that is locked with a password.
/// Note that it is the local identity that is locked, not the bunker requiring a secret.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct BunkerStateLocked {}
impl BunkerClientState for BunkerStateLocked {}
impl BunkerClient<BunkerStateLocked> {
    /// Create a new BunkerClient, generating a fresh local identity
    pub fn new(
        remote_signer_pubkey: PublicKey,
        relay_url: RelayUrl,
        connect_secret: Option<String>,
        new_password: &str,
    ) -> Result<BunkerClient<BunkerStateLocked>, Error> {
        let epk = {
            let private_key = PrivateKey::generate();
            private_key.export_encrypted(new_password, 18)?
        };

        Ok(BunkerClient {
            remote_signer_pubkey,
            relay_url,
            connect_secret,
            epk,
            state_data: BunkerStateLocked {},
        })
    }

    /// Create a new nip46 client from a URL.
    ///
    /// This connects to the relay, but does not contact the bunker yet. Use `connect()` to
    /// initiate contact with the bunker.
    pub fn new_from_url(
        url: &str,
        new_password: &str,
    ) -> Result<BunkerClient<BunkerStateLocked>, Error> {
        let Nip46ConnectionParameters {
            remote_signer_pubkey,
            relays,
            secret,
        } = Nip46ConnectionParameters::from_str(url)?;

        let epk = {
            let private_key = PrivateKey::generate();
            private_key.export_encrypted(new_password, 18)?
        };

        Ok(BunkerClient {
            remote_signer_pubkey,
            relay_url: relays[0].clone(),
            connect_secret: secret,
            epk,
            state_data: BunkerStateLocked {},
        })
    }

    /// Create a new BunkerClient from stored data. This will be in the locked state.
    pub fn from_stored_data(
        remote_signer_pubkey: PublicKey,
        relay_url: RelayUrl,
        connect_secret: Option<String>,
        epk: EncryptedPrivateKey,
    ) -> BunkerClient<BunkerStateLocked> {
        BunkerClient {
            remote_signer_pubkey,
            relay_url,
            connect_secret,
            epk,
            state_data: BunkerStateLocked {},
        }
    }

    /// Unlock the bunker client
    pub fn unlock(self, password: &str) -> Result<BunkerClient<BunkerStateUnlocked>, Error> {
        let key_signer = KeySigner::from_encrypted_private_key(self.epk.clone(), password)?;
        let arc_key_signer = Arc::new(key_signer);

        Ok(BunkerClient {
            remote_signer_pubkey: self.remote_signer_pubkey,
            relay_url: self.relay_url,
            connect_secret: self.connect_secret,
            epk: self.epk,
            state_data: BunkerStateUnlocked {
                local_identity: arc_key_signer,
            },
        })
    }
}

/// A `BunkerClient` that is unlocked but not running
#[derive(Debug)]
pub struct BunkerStateUnlocked {
    /// Our local identity in action
    local_identity: Arc<KeySigner>,
}
impl BunkerClientState for BunkerStateUnlocked {}
impl BunkerClient<BunkerStateUnlocked> {
    /// Create a new BunkerClient, generating a fresh local identity
    pub fn new(
        remote_signer_pubkey: PublicKey,
        relay_url: RelayUrl,
        connect_secret: Option<String>,
        password: &str,
    ) -> Result<BunkerClient<BunkerStateUnlocked>, Error> {
        let epk = {
            let private_key = PrivateKey::generate();
            private_key.export_encrypted(password, 18)?
        };

        let key_signer = KeySigner::from_encrypted_private_key(epk.clone(), password)?;

        Ok(BunkerClient {
            remote_signer_pubkey,
            relay_url,
            connect_secret,
            epk,
            state_data: BunkerStateUnlocked {
                local_identity: Arc::new(key_signer),
            },
        })
    }

    /// Connect to the relay
    pub async fn connect_to_relay(self) -> Result<BunkerClient<BunkerStateRelayConnected>, Error> {
        let client = client::Client::connect(
            self.relay_url.as_str(),
            Duration::from_secs(5),
            Some(self.state_data.local_identity.clone()),
        )
        .await?;

        Ok(BunkerClient {
            remote_signer_pubkey: self.remote_signer_pubkey,
            relay_url: self.relay_url,
            connect_secret: self.connect_secret,
            epk: self.epk,
            state_data: BunkerStateRelayConnected {
                local_identity: self.state_data.local_identity,
                client,
            },
        })
    }

    // TBD: lock
}

/// A `BunkerClient` that is connected to the relay, but not to the bunker
#[derive(Debug)]
pub struct BunkerStateRelayConnected {
    /// Our local identity in action
    local_identity: Arc<KeySigner>,

    /// An active client to the relay
    client: client::Client,
}
impl BunkerClientState for BunkerStateRelayConnected {}
impl BunkerClient<BunkerStateRelayConnected> {
    /// Send a `Nip46Request` and wait for a `Nip46Response` (up to our timeout)
    pub async fn call(&mut self, request: Nip46Request) -> Result<Nip46Response, Error> {
        call_fn(
            request,
            self.remote_signer_pubkey,
            self.state_data.local_identity.clone(),
            &mut self.state_data.client,
        )
        .await
    }

    /// Connect to the bunker
    pub async fn connect_to_bunker(mut self) -> Result<BunkerClient<BunkerStateConnected>, Error> {
        // Connect
        let connect_response = {
            let connect_request = {
                let params = {
                    let mut params = vec![self.remote_signer_pubkey.as_hex_string()];
                    if let Some(secret) = &self.connect_secret {
                        params.push(secret.to_owned());
                    }
                    params
                };

                Nip46Request::new("connect".to_string(), params)
            };

            self.call(connect_request).await?
        };

        // Verify there is no error
        if let Some(error) = connect_response.error {
            return Err(Error::Nip46Error(error));
        }

        // Ask for our pubkey
        let pubkey_response = {
            let pubkey_request = {
                let params = vec![];
                Nip46Request::new("get_public_key".to_string(), params)
            };

            self.call(pubkey_request).await?
        };

        // Verify there is no error
        if let Some(error) = pubkey_response.error {
            return Err(Error::Nip46Error(error));
        }

        let public_key = PublicKey::try_from_hex_string(&pubkey_response.result, true)?;

        Ok(BunkerClient {
            remote_signer_pubkey: self.remote_signer_pubkey,
            relay_url: self.relay_url,
            connect_secret: self.connect_secret,
            epk: self.epk,
            state_data: BunkerStateConnected {
                local_identity: self.state_data.local_identity,
                client: self.state_data.client,
                public_key: public_key,
            },
        })
    }

    // TBD: disconnect
    // TBD: disconnect_and_lock
}

/// A `BunkerClient` that is fully connected through to the bunker
#[derive(Debug)]
pub struct BunkerStateConnected {
    /// Our local identity in action
    local_identity: Arc<KeySigner>,

    /// An active client to the relay
    client: client::Client,

    /// The user's public key as told to us by the bunker
    public_key: PublicKey,
}
impl BunkerClientState for BunkerStateConnected {}
impl BunkerClient<BunkerStateConnected> {
    /// Send a `Nip46Request` and wait for a `Nip46Response` (up to our timeout)
    pub async fn call(&mut self, request: Nip46Request) -> Result<Nip46Response, Error> {
        call_fn(
            request,
            self.remote_signer_pubkey,
            self.state_data.local_identity.clone(),
            &mut self.state_data.client,
        )
        .await
    }

    // TBD: disconnect
    // TBD: disconnect_and_lock
}

async fn call_fn(
    request: Nip46Request,
    remote_signer_pubkey: PublicKey,
    local_identity: Arc<KeySigner>,
    client: &mut client::Client,
) -> Result<Nip46Response, Error> {
    let event = request
        .to_event(remote_signer_pubkey, local_identity.clone())
        .await?;

    // Post event to server
    let (ok, msg) = client.post_event(event).await?;
    if !ok {
        return Err(Error::Nip46FailedToPost(msg));
    }

    let mut filter = Filter::new();
    filter.add_author(remote_signer_pubkey);
    filter.add_event_kind(EventKind::NostrConnect);
    filter.add_tag_value('p', local_identity.public_key().as_hex_string());
    filter.limit = Some(1);

    // Wait for a response
    let relay_fetch_result = client.fetch_events_keep_open(filter).await?;

    let event = if !relay_fetch_result.pre_eose_events.is_empty() {
        relay_fetch_result.pre_eose_events[0].clone()
    } else if let Some(v) = relay_fetch_result.post_eose_events {
        if !v.is_empty() {
            v[0].clone()
        } else {
            return Err(Error::Nip46NoResponse);
        }
    } else {
        return Err(Error::Nip46NoResponse);
    };

    // Convert into a response
    let response: Nip46Response = serde_json::from_str(&event.content)?;

    Ok(response)
}

#[async_trait]
impl Signer for BunkerClient<BunkerStateConnected> {
    fn public_key(&self) -> PublicKey {
        self.state_data.public_key
    }

    fn encrypted_private_key(&self) -> Option<EncryptedPrivateKey> {
        unimplemented!()
    }

    async fn sign_id(&self, _id: Id) -> Result<Signature, Error> {
        unimplemented!()
    }

    async fn sign(&self, _message: &[u8]) -> Result<Signature, Error> {
        unimplemented!()
    }

    async fn encrypt(
        &self,
        _other: &PublicKey,
        _plaintext: &str,
        _algo: ContentEncryptionAlgorithm,
    ) -> Result<String, Error> {
        unimplemented!()
    }

    async fn decrypt(&self, _other: &PublicKey, _ciphertext: &str) -> Result<String, Error> {
        unimplemented!()
    }

    async fn nip44_conversation_key(&self, _other: &PublicKey) -> Result<[u8; 32], Error> {
        unimplemented!()
    }

    fn key_security(&self) -> Result<KeySecurity, Error> {
        Ok(KeySecurity::NotTracked)
    }
}

// TBD: don't implement LockableSigner since it doesn't consider our state transitions.
//   instead add a change_passphrase function and a lock function that goes backwards.

impl Serialize for BunkerClient<BunkerStateLocked> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(4))?;
        seq.serialize_element(&self.remote_signer_pubkey)?;
        seq.serialize_element(&self.relay_url)?;
        seq.serialize_element(&self.connect_secret)?;
        seq.serialize_element(&self.epk)?;
        seq.end()
    }
}

impl<'de> Deserialize<'de> for BunkerClient<BunkerStateLocked> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_seq(BunkerClientVisitor)
    }
}

struct BunkerClientVisitor;

impl<'de> Visitor<'de> for BunkerClientVisitor {
    type Value = BunkerClient<BunkerStateLocked>;

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "a bunker client structure as a sequence")
    }

    fn visit_seq<A>(self, mut access: A) -> Result<BunkerClient<BunkerStateLocked>, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let remote_signer_pubkey = access
            .next_element::<PublicKey>()?
            .ok_or_else(|| DeError::custom("Missing or invalid remote_signer_pubkey"))?;
        let relay_url = access
            .next_element::<RelayUrl>()?
            .ok_or_else(|| DeError::custom("Missing or invalid relay_url"))?;
        let connect_secret = access
            .next_element::<Option<String>>()?
            .ok_or_else(|| DeError::custom("Missing or invalid connect_secret"))?;
        let epk = access
            .next_element::<EncryptedPrivateKey>()?
            .ok_or_else(|| DeError::custom("Missing or invalid epk"))?;

        Ok(BunkerClient {
            remote_signer_pubkey,
            relay_url,
            connect_secret,
            epk,
            state_data: BunkerStateLocked {},
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_bunker_client_serde() {
        let bc = BunkerClient::<BunkerStateLocked>::new(
            PrivateKey::generate().public_key(),
            RelayUrl::try_from_str("wss://relay.example/").unwrap(),
            None,
            "password",
        )
        .unwrap();
        let s = serde_json::to_string(&bc).unwrap();
        println!("{s}");
        let bc2 = serde_json::from_str(&*s).unwrap();
        assert_eq!(bc, bc2);
    }
}
