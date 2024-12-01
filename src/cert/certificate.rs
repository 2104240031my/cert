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

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum AeadAlgorithm {
    Aes256Gcm = 0x00000001,
}

#[derive(Clone, Copy, PartialEq, Eq)]
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

    pub fn to_bytes(&self, buf: &mut [u8]) -> Result<usize, CertError> {

        if buf.len() < Self::BYTES_LEN {
            return Err(CertError::new(CertErrorCode::BufferTooShort));
        }

        buf[0..4].copy_from_slice(&(*self as u32).to_be_bytes());

        return Ok(Self::BYTES_LEN);

    }

}

#[derive(Clone, Copy, PartialEq, Eq)]
enum CertificateType {
    SubjectAuthOnly = 0x0001,
    // SubjectAuthAndSubjectSignKey = 0x0002,
}

impl CertificateType {
    pub const BYTES_LEN: usize = 2;
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

struct IdentityFixedU64 {
    inner: u64
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
    identity: IdentityFixedU64,
    validity_period: ValidityPeriodFixedU64Pair,
    // --- to here ---

    signature: [u8; MAX_SIGN_SIGNATURE_LEN]

}

impl IdentityFixedU64 {

    pub const BYTES_LEN: usize = 8;

    pub fn to_bytes(&self, buf: &mut [u8]) -> Result<usize, CertError> {

        if buf.len() < Self::BYTES_LEN {
            return Err(CertError::new(CertErrorCode::BufferTooShort));
        }

        buf[0..8].copy_from_slice(&self.inner.to_be_bytes());

        return Ok(Self::BYTES_LEN);

    }

}

impl ValidityPeriodFixedU64Pair {

    pub const BYTES_LEN: usize = 16;

    pub fn to_bytes(&self, buf: &mut [u8]) -> Result<usize, CertError> {

        if buf.len() < Self::BYTES_LEN {
            return Err(CertError::new(CertErrorCode::BufferTooShort));
        }

        buf[0..8].copy_from_slice(&self.not_before.to_be_bytes());
        buf[8..16].copy_from_slice(&self.not_after.to_be_bytes());

        return Ok(Self::BYTES_LEN);

    }

}

impl CertificateCommonHeader {

    pub const BYTES_LEN: usize = CertificateType::BYTES_LEN + 2;

    pub fn to_bytes(&self, buf: &mut [u8]) -> Result<usize, CertError> {

        if buf.len() < Self::BYTES_LEN {
            return Err(CertError::new(CertErrorCode::BufferTooShort));
        }

        buf[0..2].copy_from_slice(&(self.cert_type as u16).to_be_bytes());
        buf[2..4].copy_from_slice(&self.length.to_be_bytes());

        return Ok(Self::BYTES_LEN);

    }

}

impl CertificateSubjectAuthOnly {

    pub fn new(sign_algo: SignAlgorithm, key_pair_id: &[u8], identity: u64, not_before: u64,
        not_after: u64) -> Result<Self, CertError> {

        let len =
            CertificateCommonHeader::BYTES_LEN +
            SignAlgorithm::BYTES_LEN +
            key_pair_id.len() +
            64 +
            8 +
            ValidityPeriodFixedU64Pair::BYTES_LEN +
            sign_algo.signature_len();

        let mut v = Self{
            common: CertificateCommonHeader{
                cert_type: CertificateType::SubjectAuthOnly,
                length: len as u16,
            },
            sign_algo: sign_algo,
            key_pair_id: Vec::<u8>::with_capacity(key_pair_id.len()),
            random: [0; 64],
            identity: IdentityFixedU64{ inner: identity },
            validity_period: ValidityPeriodFixedU64Pair{
                not_before: not_before,
                not_after: not_after
            },
            signature: [0; MAX_SIGN_SIGNATURE_LEN]
        };

        v.key_pair_id.copy_from_slice(key_pair_id);

        let mut csprng = ChaCha20Rng::from_entropy();
        csprng.fill_bytes(&mut v.random[..]);

        return Ok(v);

    }

    pub fn to_bytes(&self, buf: &mut [u8]) -> Result<usize, CertError> {

        let len =
            CertificateCommonHeader::BYTES_LEN +
            SignAlgorithm::BYTES_LEN +
            self.key_pair_id.len() +
            64 +
            8 +
            ValidityPeriodFixedU64Pair::BYTES_LEN +
            self.sign_algo.signature_len();

        if buf.len() < len {
            return Err(CertError::new(CertErrorCode::BufferTooShort));
        }

        self.common.to_bytes(&mut buf[..]).unwrap();
        self.sign_algo.to_bytes(&mut buf[CertificateCommonHeader::BYTES_LEN..]).unwrap();

        let i = CertificateCommonHeader::BYTES_LEN + SignAlgorithm::BYTES_LEN;
        buf[i..(i + self.key_pair_id.len())].copy_from_slice(&self.key_pair_id);

        let i = i + self.key_pair_id.len();
        buf[i..(i + 64)].copy_from_slice(&self.random);

        let i = i + 64;
        self.identity.to_bytes(&mut buf[i..]).unwrap();

        let i = i + IdentityFixedU64::BYTES_LEN;
        self.validity_period.to_bytes(&mut buf[i..]).unwrap();

        let i = i + ValidityPeriodFixedU64Pair::BYTES_LEN;
        buf[i..(i + self.signature.len())]
            .copy_from_slice(&self.signature[..self.sign_algo.signature_len()]);

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