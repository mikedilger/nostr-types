use crate::{
    client, ContentEncryptionAlgorithm, EncryptedPrivateKey, Error, Event, EventKind, Filter,
    KeySecurity, KeySigner, LockableSigner, PreEvent, PublicKey, RelayUrl, Signer,
};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

mod request;
pub use request::Nip46Request;

mod response;
pub use response::Nip46Response;

mod params;
pub use params::Nip46ConnectionParameters;

mod prebunk;
pub use prebunk::PreBunkerClient;

/// This is a NIP-46 Bunker client
#[derive(Debug, Serialize, Deserialize)]
pub struct BunkerClient {
    /// The pubkey of the bunker
    pub remote_signer_pubkey: PublicKey,

    /// The relay the bunker is listening at
    pub relay_url: RelayUrl,

    /// Our local identity
    pub local_signer: Arc<KeySigner>,

    /// User Public Key
    pub public_key: PublicKey,

    /// Client
    #[serde(skip)]
    pub client: RwLock<Option<client::Client>>,
}

impl BunkerClient {
    /// Create a new BunkerClient from stored data. This will be in the locked state.
    pub fn from_stored_data(
        remote_signer_pubkey: PublicKey,
        relay_url: RelayUrl,
        keysigner: KeySigner,
        public_key: PublicKey,
    ) -> BunkerClient {
        BunkerClient {
            remote_signer_pubkey,
            relay_url,
            local_signer: Arc::new(keysigner),
            public_key,
            client: RwLock::new(None),
        }
    }

    /// Is the signer locked?
    pub fn is_locked(&self) -> bool {
        self.local_signer.is_locked()
    }

    /// Unlock (if locked)
    pub fn unlock(&self, password: &str) -> Result<(), Error> {
        self.local_signer.unlock(password)
    }

    /// Change passphrase
    pub fn change_passphrase(&self, old: &str, new: &str, log_n: u8) -> Result<(), Error> {
        self.local_signer.change_passphrase(old, new, log_n)
    }

    /// Is the signer connected to the relay?
    pub async fn is_connected(&self) -> bool {
        self.client.read().await.is_some()
    }

    /// Connect to the relay
    pub async fn connect(&self) -> Result<(), Error> {
        if self.is_connected().await {
            return Ok(());
        }

        *self.client.write().await = Some(
            client::Client::connect(
                self.relay_url.as_str(),
                Duration::from_secs(5),
                Some(self.local_signer.clone()),
            )
            .await?,
        );

        Ok(())
    }

    /// Send a `Nip46Request` and wait for a `Nip46Response` (up to our timeout)
    pub async fn call(&self, request: Nip46Request) -> Result<Nip46Response, Error> {
        if !self.is_connected().await {
            return Err(Error::Nip46Error("Not Connected to Relay".to_owned()));
        }

        let event = request
            .to_event(self.remote_signer_pubkey, self.local_signer.clone())
            .await?;

        // Post event to server
        let (ok, msg) = self
            .client
            .write()
            .await
            .as_mut()
            .unwrap()
            .post_event(event)
            .await?;
        if !ok {
            return Err(Error::Nip46FailedToPost(msg));
        }

        let mut filter = Filter::new();
        filter.add_author(self.remote_signer_pubkey);
        filter.add_event_kind(EventKind::NostrConnect);
        filter.add_tag_value('p', self.local_signer.public_key().as_hex_string());
        filter.limit = Some(1);
        let sub_id = self
            .client
            .write()
            .await
            .as_mut()
            .unwrap()
            .subscribe(filter.clone())
            .await?;

        // Wait for a response
        let relay_fetch_result = self
            .client
            .write()
            .await
            .as_mut()
            .unwrap()
            .fetch_events_keep_open(sub_id, filter)
            .await?;

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

    /// Disconnect from the relay
    pub async fn disconnect(&self) {
        *self.client.write().await = None;
    }

    /// Disconnect from the relay and lock
    pub async fn disconnect_and_lock(&self) {
        self.disconnect().await;
        self.local_signer.lock();
    }
}

#[async_trait]
impl Signer for BunkerClient {
    fn public_key(&self) -> PublicKey {
        self.public_key
    }

    fn encrypted_private_key(&self) -> Option<EncryptedPrivateKey> {
        // NIP-46 does not offer an export function (yet)
        None
    }

    async fn sign_event(&self, pre_event: PreEvent) -> Result<Event, Error> {
        if self.is_locked() {
            return Err(Error::SignerIsLocked);
        }
        if !self.is_connected().await {
            self.connect().await?;
        }

        let pre_event_string = serde_json::to_string(&pre_event)?;
        let request = Nip46Request::new("sign_event".to_owned(), vec![pre_event_string]);
        let response = self.call(request).await?;
        if let Some(error) = response.error {
            if !error.is_empty() {
                return Err(Error::Nip46Error(error));
            }
        }
        let event: Event = serde_json::from_str(&response.result)?;
        Ok(event)
    }

    async fn encrypt(
        &self,
        other: &PublicKey,
        plaintext: &str,
        algo: ContentEncryptionAlgorithm,
    ) -> Result<String, Error> {
        if self.is_locked() {
            return Err(Error::SignerIsLocked);
        }
        if !self.is_connected().await {
            self.connect().await?;
        }

        let cmd = match algo {
            ContentEncryptionAlgorithm::Nip04 => "nip04_encrypt",
            ContentEncryptionAlgorithm::Nip44v1Unpadded => return Err(Error::UnsupportedAlgorithm),
            ContentEncryptionAlgorithm::Nip44v1Padded => return Err(Error::UnsupportedAlgorithm),
            ContentEncryptionAlgorithm::Nip44v2 => "nip44_encrypt",
        };

        let request = Nip46Request::new(
            cmd.to_owned(),
            vec![other.as_hex_string(), plaintext.to_owned()],
        );

        let response = self.call(request).await?;
        if let Some(error) = response.error {
            if !error.is_empty() {
                return Err(Error::Nip46Error(error));
            }
        }

        let ciphertext: String = serde_json::from_str(&response.result)?;

        Ok(ciphertext)
    }

    async fn decrypt(&self, other: &PublicKey, ciphertext: &str) -> Result<String, Error> {
        if self.is_locked() {
            return Err(Error::SignerIsLocked);
        }
        if !self.is_connected().await {
            self.connect().await?;
        }

        let cmd = if ciphertext.contains("?iv=") {
            "nip04_decrypt"
        } else {
            "nip44_decrypt"
        };

        let request = Nip46Request::new(
            cmd.to_owned(),
            vec![other.as_hex_string(), ciphertext.to_owned()],
        );

        let response = self.call(request).await?;
        if let Some(error) = response.error {
            if !error.is_empty() {
                return Err(Error::Nip46Error(error));
            }
        }

        let plaintext: String = serde_json::from_str(&response.result)?;

        Ok(plaintext)
    }

    fn key_security(&self) -> Result<KeySecurity, Error> {
        Ok(KeySecurity::NotTracked)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::PrivateKey;

    #[test]
    fn test_bunker_client_serde() {
        let prebunk = PreBunkerClient::new(
            PrivateKey::generate().public_key(),
            RelayUrl::try_from_str("wss://relay.example/").unwrap(),
            None,
            "password",
        )
        .unwrap();

        let s = serde_json::to_string(&prebunk).unwrap();
        println!("{s}");
        let prebunk2: PreBunkerClient = serde_json::from_str(&*s).unwrap();
        assert_eq!(prebunk.remote_signer_pubkey, prebunk2.remote_signer_pubkey);
        assert_eq!(prebunk.relay_url, prebunk2.relay_url);
        assert_eq!(prebunk.connect_secret, prebunk2.connect_secret);
        assert_eq!(
            prebunk.local_signer.encrypted_private_key(),
            prebunk2.local_signer.encrypted_private_key()
        );
    }
}
