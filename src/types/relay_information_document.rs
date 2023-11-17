use crate::versioned::relay_information_document::{
    FeeV1, RelayFeesV1, RelayInformationDocumentV1, RelayLimitationV1, RelayRetentionV1,
};

/// Relay limitations
pub type RelayLimitation = RelayLimitationV1;

/// Relay retention
pub type RelayRetention = RelayRetentionV1;

/// Fee
pub type Fee = FeeV1;

/// Relay fees
pub type RelayFees = RelayFeesV1;

/// Relay information document as described in NIP-11, supplied by a relay
pub type RelayInformationDocument = RelayInformationDocumentV1;
