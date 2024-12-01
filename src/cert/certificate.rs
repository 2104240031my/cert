use cryptopkg::crypto::feature::Aead as AeadFeature;
use cryptopkg::crypto::feature::DiffieHellman as DiffieHellmanFeature;
use cryptopkg::crypto::feature::DigitalSignatureSigner as DigitalSignatureSignerFeature;
use cryptopkg::crypto::feature::DigitalSignatureVerifier as DigitalSignatureVerifierFeature;
use cryptopkg::crypto::feature::Hash as HashFeature;
use cryptopkg::crypto::feature::Mac as MacFeature;
use cryptopkg::crypto::aes_aead::Aes256Gcm;
use cryptopkg::crypto::ed25519::Ed25519;
use cryptopkg::crypto::ed25519::Ed25519Signer;
use cryptopkg::crypto::ed25519::Ed25519Verifier;
use cryptopkg::crypto::hmac_sha3::HmacSha3256;
use cryptopkg::crypto::sha3::Sha3256;
use cryptopkg::crypto::x25519::X25519;
use rand_core::RngCore;
use rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::collections::HashMap;
use std::sync::LazyLock;
use std::sync::Mutex;
use crate::cert::error::CertError;
use crate::cert::error::CertErrorCode;

const MAX_SIGN_PRIVATE_KEY_LEN: usize    = Ed25519::PRIVATE_KEY_LEN;
const MAX_SIGN_PUBLIC_KEY_LEN: usize     = Ed25519::PUBLIC_KEY_LEN;
const MAX_SIGN_SIGNATURE_LEN: usize      = Ed25519::SIGNATURE_LEN;
const MAX_AEAD_KEY_LEN: usize            = Aes256Gcm::KEY_LEN;
const MAX_AEAD_NONCE_LEN: usize          = Aes256Gcm::MAX_NONCE_LEN;
const MAX_AEAD_TAG_LEN: usize            = Aes256Gcm::TAG_LEN;
const MAX_HASH_MESSAGE_DIGEST_LEN: usize = Sha3256::MESSAGE_DIGEST_LEN;

pub enum AeadAlgorithm {
    Aes256Gcm = 0x00000001,
}

pub enum SignAlgorithm {
    Ed25519 = 0x00000001,
}

impl SignAlgorithm {

    pub const BYTES_LEN: usize = 4;

    pub fn signature_len(&self) -> usize {
        return match self {
            Self::Ed25519 => Ed25519::SIGNATURE_LEN,
        };
    }

}

enum CertificateType {
    SubjectAuthOnly = 0x0001,
    // SubjectAuthAndSubjectSignKey = 0x0002,
}

pub enum Certificate {
    SubjectAuthOnly(CertificateSubjectAuthOnly),
    // SubjectAuthAndSubjectSignKey(CertificateSubjectAuthAndSubjectSignKey)
}

struct CertificateEnvelope {
    aead_algo: AeadAlgorithm,
    aead_nonce: [u8; MAX_AEAD_NONCE_LEN],
    aead_payload_len: u16,
    aead_payload: Certificate,
    aead_tag: [u8; MAX_AEAD_TAG_LEN]
}

struct CertificateCommonHeader {
    cert_type: CertificateType,
    length: u16, // length from self.cert_type to self.signature
}

struct ValidityPeriodFixedU64Pair {
    not_before: u64,
    not_after: u64
}

pub struct CertificateSubjectAuthOnly {

    // --- input data for sign is from here ---
    common: CertificateCommonHeader, // .cert_type = CertificateType::CertificateSubjectAuthOnly
    sign_algo: SignAlgorithm,
    key_pair_id: Vec<u8>,
    random: [u8; 64],
    identity: u64,
    validity_period: ValidityPeriodFixedU64Pair,
    // --- to here ---

    signature: [u8; MAX_SIGN_SIGNATURE_LEN]

}

impl ValidityPeriodFixedU64Pair {

    pub const BYTES_LEN: usize = 16;

    pub fn to_bytes(&self, buf: &mut [u8]) -> Result<usize, CertError> {

        if buf.len() < 16 {
            return Err(CertError::new(CertErrorCode::BufferTooShort));
        }

        let not_before: [u8; 8] = self.not_before.to_be_bytes();
        let not_after: [u8; 8] = self.not_after.to_be_bytes();

        buf[0..8].copy_from_slice(&not_before[..]);
        buf[8..16].copy_from_slice(&not_after[..]);

        return Ok(16);

    }

}

impl CertificateCommonHeader {

    pub const BYTES_LEN: usize = 4;

    pub fn to_bytes(&self, buf: &mut [u8]) -> Result<usize, CertError> {

        if buf.len() < 4 {
            return Err(CertError::new(CertErrorCode::BufferTooShort));
        }

        return Ok(4);

    }

}

impl CertificateSubjectAuthOnly {

    pub fn new(sign_algo: SignAlgorithm, key_pair_id: &[u8], identity: u64, not_before: u64,
        not_after: u64) -> Result<Self, CertError> {

        let len: usize =
            CertificateCommonHeader::BYTES_LEN +
            SignAlgorithm::BYTES_LEN +
            key_pair_id.len() +
            64 +
            8 +
            ValidityPeriodFixedU64Pair::BYTES_LEN +
            sign_algo.signature_len();

        let mut v: Self = Self{
            common: CertificateCommonHeader{
                cert_type: CertificateType::SubjectAuthOnly,
                length: len as u16,
            },
            sign_algo: sign_algo,
            key_pair_id: Vec::<u8>::with_capacity(key_pair_id.len()),
            random: [0; 64],
            identity: identity,
            validity_period: ValidityPeriodFixedU64Pair{
                not_before: not_before,
                not_after: not_after
            },
            signature: [0; MAX_SIGN_SIGNATURE_LEN]
        };

        v.key_pair_id.copy_from_slice(key_pair_id);

        let mut csprng: ChaCha20Rng = ChaCha20Rng::from_entropy();
        csprng.fill_bytes(&mut v.random[..]);

        return Ok(v);

    }

    pub fn to_bytes(&self, buf: &mut [u8]) -> Result<usize, CertError> {

        let len: usize =
            CertificateCommonHeader::BYTES_LEN +
            SignAlgorithm::BYTES_LEN +
            self.key_pair_id.len() +
            64 +
            8 +
            ValidityPeriodFixedU64Pair::BYTES_LEN +
            self.sign_algo.signature_len();

/*        if buf.len() < len {
            return Err(CertError::new(CertErrorCode::BufferTooShort));
        }

        buf[0] = self.sign_algo as u8;
        buf[1] = self.sign_algo as u8;
        buf[2] = self.sign_algo as u8;

        buf[bytes.len()..(bytes.len() + 2)].copy_from_slice(&signer_key_pair_id.len().to_be_bytes()[..]);

        bytes.push(self.sign_algo as u8);

        bytes[bytes.len()..(bytes.len() + signer_key_pair_id.len())].copy_from_slice(signer_key_pair_id);
        bytes[bytes.len()..(bytes.len() + 64)].copy_from_slice(&random[..]);

        match identity {
            FixedU64(v) => {
                bytes.push(IdentityType.FixedU64 as u8);
                bytes[bytes.len()..(bytes.len() + 8)].copy_from_slice(&v.to_be_bytes()[..]);
            },
        }

        match validity_period {
            ValidityPeriod(v) => {
                bytes.push(ValidityPeriodType.FixedU64Pair as u8);
                bytes[bytes.len()..(bytes.len() + 8)].copy_from_slice(&v.not_before.to_be_bytes()[..]);
                bytes[bytes.len()..(bytes.len() + 8)].copy_from_slice(&v.not_after.to_be_bytes()[..]);
            },
        }
*/
        return Ok(len);

    }

}

// struct CertificateSubjectAuthAndSubjectSignKey {
//     sign_to: struct {
//         sign_algo: SignAlgorithm,
//         signer_key_pair_id_len: u16,
//         signer_key_pair_id: [u8; BUFFER_SIZE],
//         random: [u8; 64],
//         identity_type: IdentityType,
//         identity: Identity,
//         validity_period_type: ValidityPeriodType,
//         validity_period: ValidityPeriod,
//         fingerprint_algo: HashAlgorithm,
//         subject_sign_key_fingerprint: [u8; BUFFER_SIZE] // Hash(ContextString + subject_sign_key.aead_payload.sign_key)
//         // ここで生のsignkeyじゃなくてfingerprintとすることで、利用者がいつでもパスワード（subject_sign_keyを暗号化するための）を変更可能になる。
//     },
//     signature: [u8; BUFFER_SIZE], // lengthはSignAlgorithmに紐づけ
//     subject_sign_key_envelope: struct {
//         length: u16,
//         content: struct {
//             aead_algo: AeadAlgorithm,
//             kdf_algo: KdfAlgorithm, // KDFでnonceも導出、よってnonceは格納フィールドはない
//             aead_payload: struct {
//                 sign_algo: SignAlgorithm,
//                 sign_key: [u8; BUFFER_SIZE]
//             },
//             aead_tag: [u8; BUFFER_SIZE] // lengthはAeadAlgorithmに紐づけ
//         }
//     }
// }