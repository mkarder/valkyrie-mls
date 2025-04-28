use std::error::Error;
use std::fmt;

#[derive(Debug)]
pub enum CredentialError {
    InvalidSignature,
    InvalidSignatureKey,
    UnknownIssuer,
    Expired,
    DecodingError,
    ClockError,
    UnsupportedCredentialType,
    VerifyingError,
    IssuerEncodingError,
    FileReadError,
    FileWriteError,
    IdentityNotU32,
    SerializationError,
}

impl fmt::Display for CredentialError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let description = match self {
            CredentialError::InvalidSignature => "Invalid signature",
            CredentialError::InvalidSignatureKey => "Credential key mismatch",
            CredentialError::UnknownIssuer => "Unknown issuer",
            CredentialError::Expired => "Credential has expired",
            CredentialError::DecodingError => "Failed to decode credential",
            CredentialError::ClockError => "System clock error",
            CredentialError::UnsupportedCredentialType => "Unsupported credential type",
            CredentialError::VerifyingError => "Error verifying signature",
            CredentialError::IssuerEncodingError => "Failed to encode issuer name",
            CredentialError::FileReadError => "Error reading from file",
            CredentialError::FileWriteError => "Error writing to file",
            CredentialError::IdentityNotU32 => {
                "Subject or issuer identity could not be parsed as u32"
            }
            CredentialError::SerializationError => {
                "Error serializing or deserializing credential data"
            }
        };
        write!(f, "{}", description)
    }
}

impl Error for CredentialError {}
