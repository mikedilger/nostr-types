pub(crate) mod relay_information_document;
pub use relay_information_document::{
    FeeV1, RelayFeesV1, RelayInformationDocumentV1, RelayLimitationV1, RelayRetentionV1,
};

pub(crate) mod relay_list;
pub use relay_list::{SimpleRelayListV1, SimpleRelayUsageV1};
