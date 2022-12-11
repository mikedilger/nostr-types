use std::fmt;

/// Errors that can occur in the nostr-proto crate
#[derive(Debug)]
pub enum Error {
    /// Base64 error
    Base64(base64::DecodeError),

    /// Signature error
    Signature(k256::ecdsa::Error),

    /// Event is in the future
    EventInFuture,

    /// Formatting error
    Fmt(std::fmt::Error),

    /// A hash mismatch verification error
    HashMismatch,

    /// Hex string decoding error
    HexDecode(hex::FromHexError),

    /// Invalid encrypted private key
    InvalidEncryptedPrivateKey,

    /// Serialization error
    SerdeJson(serde_json::Error),

    /// Try from slice error
    Slice(std::array::TryFromSliceError),

    /// Time error
    Time(std::time::SystemTimeError),

    /// Unknown event kind
    UnknownEventKind(u64),

    /// Unknown Key Security
    UnknownKeySecurity(u8),

    /// Unpad error
    Unpad(aes::cipher::block_padding::UnpadError),

    /// Wrong length hex string
    WrongLengthHexString,

    /// Wrong Decryption Password
    WrongDecryptionPassword,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::Base64(ref e) => write!(f, "Base64 decode error: {}", e),
            Error::Signature(ref e) => write!(f, "Signature error: {:?}", e),
            Error::EventInFuture => write!(f, "Event is in the future!"),
            Error::Fmt(ref e) => write!(f, "Formatting error: {:?}", e),
            Error::HashMismatch => write!(f, "Hash mismatch"),
            Error::HexDecode(ref e) => write!(f, "Hex decode error: {:?}", e),
            Error::InvalidEncryptedPrivateKey => write!(f, "Invalid encrypted private key"),
            Error::SerdeJson(ref e) => write!(f, "JSON (de)serialization error: {:?}", e),
            Error::Slice(ref e) => write!(f, "Try from slice error: {}", e),
            Error::Time(ref e) => write!(f, "System time error: {:?}", e),
            Error::UnknownEventKind(u) => write!(f, "Unknown event kind: {}", u),
            Error::UnknownKeySecurity(i) => write!(f, "Unknown key security: {}", i),
            Error::Unpad(e) => write!(f, "AES decrypt unpad error: {}", e),
            Error::WrongLengthHexString => write!(f, "Wrong length hex string"),
            Error::WrongDecryptionPassword => write!(f, "Wrong decryption password"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match *self {
            Error::Base64(ref e) => Some(e),
            Error::Signature(ref e) => Some(e),
            Error::Fmt(ref e) => Some(e),
            Error::HexDecode(ref e) => Some(e),
            Error::SerdeJson(ref e) => Some(e),
            Error::Slice(ref e) => Some(e),
            Error::Time(ref e) => Some(e),
            Error::Unpad(ref e) => Some(e),
            _ => None,
        }
    }
}

impl From<base64::DecodeError> for Error {
    fn from(e: base64::DecodeError) -> Error {
        Error::Base64(e)
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

impl From<std::array::TryFromSliceError> for Error {
    fn from(e: std::array::TryFromSliceError) -> Error {
        Error::Slice(e)
    }
}

impl From<std::time::SystemTimeError> for Error {
    fn from(e: std::time::SystemTimeError) -> Error {
        Error::Time(e)
    }
}

impl From<aes::cipher::block_padding::UnpadError> for Error {
    fn from(e: aes::cipher::block_padding::UnpadError) -> Error {
        Error::Unpad(e)
    }
}
