#[derive(Debug, Copy, Clone)]
pub enum CertErrorCode {

    // general
    Unknown,
    IllegalArgument,

    // specific
    UnsupportedAlgorithm,
    BufferLengthIncorrect,
    VerificationFailed

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
            CertErrorCode::BufferLengthIsNotMultipleOfBlockSize => "buffer length is not multiple of block size",
            CertErrorCode::CounterOverwrapped                   => "counter overwrapped",
            CertErrorCode::VerificationFailed                   => "verification failed"
        });
    }

}

impl Error for CertError {}