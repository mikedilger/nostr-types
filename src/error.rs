use std::fmt;

/// Errors that can occur in the nostr-proto crate
#[derive(Debug)]
pub enum Error {
    /// Signature error
    Signature(k256::ecdsa::Error),

    /// Formatting error
    Fmt(std::fmt::Error),

    /// A hash mismatch verification error
    HashMismatch,

    /// Hex string decoding error
    HexDecode(hex::FromHexError),

    /// Serialization error
    SerdeJson(serde_json::Error),

    /// Unknown event kind
    UnknownEventKind(u64),

    /// Wrong length hex string
    WrongLengthHexString,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::Signature(ref e) => write!(f, "Signature error: {:?}", e),
            Error::Fmt(ref e) => write!(f, "Formatting error: {:?}", e),
            Error::HashMismatch => write!(f, "Hash mismatch"),
            Error::HexDecode(ref e) => write!(f, "Hex decode error: {:?}", e),
            Error::SerdeJson(ref e) => write!(f, "JSON (de)serialization error: {:?}", e),
            Error::UnknownEventKind(u) => write!(f, "Unknown event kind: {}", u),
            Error::WrongLengthHexString => write!(f, "Wrong length hex string"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match *self {
            Error::Signature(ref e) => Some(e),
            Error::Fmt(ref e) => Some(e),
            Error::HexDecode(ref e) => Some(e),
            Error::SerdeJson(ref e) => Some(e),
            _ => None,
        }
    }
}

impl From<k256::ecdsa::Error> for Error {
    fn from(e: k256::ecdsa::Error) -> Error {
        Error::Signature(e)
    }
}

impl From<std::fmt::Error> for Error {
    fn from(e: std::fmt::Error) -> Error {
        Error::Fmt(e)
    }
}

impl From<hex::FromHexError> for Error {
    fn from(e: hex::FromHexError) -> Error {
        Error::HexDecode(e)
    }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Error {
        Error::SerdeJson(e)
    }
}
