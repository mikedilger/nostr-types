use super::{EventKind, PrivateKey, PublicKey, PublicKeyHex, Signature, SignatureHex, Unixtime};
use crate::Error;
use serde::de::Error as DeError;
use serde::de::{Deserialize, Deserializer, Visitor};
use serde::ser::{Serialize, Serializer};
use std::fmt;

/// Delegation information for an Event
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EventDelegation {
    /// The event was not delegated
    NotDelegated,

    /// The delegation was invalid (with reason)
    InvalidDelegation(String),

    /// The event was delegated and is valid (with pubkey of delegator)
    DelegatedBy(PublicKey),
}

/// Conditions of delegation
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct DelegationConditions {
    /// If the delegation is only for a given event kind
    pub kind: Option<EventKind>,

    /// If the delegation is only for events created after a certain time
    pub created_after: Option<Unixtime>,

    /// If the delegation is only for events created before a certain time
    pub created_before: Option<Unixtime>,
}

impl DelegationConditions {
    /// Convert to string form
    pub fn as_string(&self) -> String {
        let mut parts: Vec<String> = Vec::new();
        if let Some(kind) = self.kind {
            parts.push(format!("kind={}", u64::from(kind)));
        }
        if let Some(created_after) = self.created_after {
            parts.push(format!("created_at>{}", created_after.0));
        }
        if let Some(created_before) = self.created_before {
            parts.push(format!("created_at<{}", created_before.0));
        }
        parts.join("&")
    }

    /// Convert from string from
    pub fn try_from_str(s: &str) -> Result<DelegationConditions, Error> {
        let mut output: DelegationConditions = Default::default();

        let parts = s.split('&');
        for part in parts {
            if let Some(kindstr) = part.strip_prefix("kind=") {
                let event_num = kindstr.parse::<u64>()?;
                let event_kind: EventKind = From::from(event_num);
                output.kind = Some(event_kind);
            }
            if let Some(timestr) = part.strip_prefix("created_at>") {
                let time = timestr.parse::<i64>()?;
                output.created_after = Some(Unixtime(time));
            }
            if let Some(timestr) = part.strip_prefix("created_at<") {
                let time = timestr.parse::<i64>()?;
                output.created_before = Some(Unixtime(time));
            }
        }
        Ok(output)
    }

    #[allow(dead_code)]
    pub(crate) fn mock() -> DelegationConditions {
        DelegationConditions {
            kind: Some(EventKind::Repost),
            created_after: Some(Unixtime(1677700000)),
            created_before: None,
        }
    }

    /// Generate the signature part of a Delegation tag
    pub fn generate_signature(
        &self,
        pubkey: PublicKeyHex,
        private_key: PrivateKey,
    ) -> Result<SignatureHex, Error> {
        let input = format!("nostr:delegation:{}:{}", pubkey, self.as_string());
        let signature = private_key.sign(input.as_bytes())?;
        Ok(signature.into())
    }

    /// Verify the signature part of a Delegation tag
    pub fn verify_signature(
        &self,
        pubkey_delegater: &PublicKey,
        pubkey_delegatee: &PublicKey,
        signature: Signature,
    ) -> Result<(), Error> {
        let input = format!(
            "nostr:delegation:{}:{}",
            pubkey_delegatee.as_hex_string(),
            self.as_string()
        );
        pubkey_delegater.verify(input.as_bytes(), signature)
    }
}

impl Serialize for DelegationConditions {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.as_string())
    }
}

impl<'de> Deserialize<'de> for DelegationConditions {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_str(DelegationConditionsVisitor)
    }
}

struct DelegationConditionsVisitor;

impl Visitor<'_> for DelegationConditionsVisitor {
    type Value = DelegationConditions;

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "A string")
    }

    fn visit_str<E>(self, v: &str) -> Result<DelegationConditions, E>
    where
        E: DeError,
    {
        DelegationConditions::try_from_str(v).map_err(|e| E::custom(format!("{}", e)))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    test_serde! {DelegationConditions, test_delegation_conditions_serde}
}
