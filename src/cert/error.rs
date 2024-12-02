use std::error::Error;
use std::fmt::Display;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum CertErrorCode {

    // general
    Unknown,
    IllegalArgument,

    // specific
    UnsupportedAlgorithm,
    BufferLengthIncorrect,
    BufferTooShort,
    SignFailed,
    VerificationFailed,
    UnsupportedCertificateType,
    UnsupportedIdentityType,
    UnsupportedValidityPeriodType,

}

#[derive(Debug)]
pub struct CertError {
    err_code: CertErrorCode
}

impl CertError {

    pub fn new(err_code: CertErrorCode) -> Self {
        return Self{
            err_code: err_code,
        };
    }

    pub fn err_code(&self) -> CertErrorCode {
        return self.err_code;
    }

}

impl Display for CertError {

    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        return write!(f, "CertError: {}", match &self.err_code {
            CertErrorCode::Unknown                              => "unknown",
            CertErrorCode::IllegalArgument                      => "illegal argument",
            CertErrorCode::UnsupportedAlgorithm                 => "unsupported algorithm",
            CertErrorCode::BufferLengthIncorrect                => "buffer length incorrect",
            CertErrorCode::BufferTooShort => "buffer too short",
            CertErrorCode::SignFailed           => "SignFailed",
            CertErrorCode::VerificationFailed                   => "verification failed",
            CertErrorCode::UnsupportedIdentityType              => "UnsupportedIdentityType",
            CertErrorCode::UnsupportedValidityPeriodType              => "UnsupportedValidityPeriodType",
            CertErrorCode::UnsupportedCertificateType           => "UnsupportedCertificateType",
        });
    }

}

impl Error for CertError {}