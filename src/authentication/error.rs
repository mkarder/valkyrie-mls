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
}
