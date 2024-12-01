mod cert;

use crate::cert::certificate::SignAlgorithm;
use crate::cert::certificate::CertificateSubjectAuthOnly;

fn main() {

    let cert = CertificateSubjectAuthOnly::new(SignAlgorithm::Ed25519, &[0; 0], 0, 0, 0).unwrap();

}