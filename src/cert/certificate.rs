use cryptopkg::crypto::feature::Aead as AeadFeature;
use cryptopkg::crypto::feature::DigitalSignatureSigner as DigitalSignatureSignerFeature;
use cryptopkg::crypto::feature::DigitalSignatureVerifier as DigitalSignatureVerifierFeature;
use cryptopkg::crypto::aes_aead::Aes256Gcm;
use cryptopkg::crypto::ed25519::Ed25519;
use cryptopkg::crypto::ed25519::Ed25519Signer;
use cryptopkg::crypto::ed25519::Ed25519Verifier;
use rand_core::RngCore;
use rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use crate::cert::error::CertError;
use crate::cert::error::CertErrorCode;

const MAX_SIGN_PRIVATE_KEY_LEN: usize    = Ed25519::PRIVATE_KEY_LEN;
const MAX_SIGN_PUBLIC_KEY_LEN: usize     = Ed25519::PUBLIC_KEY_LEN;
const MAX_SIGN_SIGNATURE_LEN: usize      = Ed25519::SIGNATURE_LEN;
const MAX_AEAD_KEY_LEN: usize            = Aes256Gcm::KEY_LEN;
const MAX_AEAD_NONCE_LEN: usize          = Aes256Gcm::MAX_NONCE_LEN;
const MAX_AEAD_TAG_LEN: usize            = Aes256Gcm::TAG_LEN;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum AeadAlgorithm {
    Aes256Gcm = 0x00000001,
}

impl AeadAlgorithm {

    pub const BYTES_LEN: usize = 4;

    pub fn key_len(&self) -> usize {
        return match self {
            Self::Aes256Gcm => Aes256Gcm::KEY_LEN,
        };
    }

    pub fn nonce_len(&self) -> usize {
        return match self {
            Self::Aes256Gcm => Aes256Gcm::MAX_NONCE_LEN,
        };
    }

    pub fn tag_len(&self) -> usize {
        return match self {
            Self::Aes256Gcm => Aes256Gcm::TAG_LEN,
        };
    }

    pub fn from_bytes(buf: &[u8]) -> Result<Self, CertError> {

        if buf.len() < Self::BYTES_LEN {
            return Err(CertError::new(CertErrorCode::BufferTooShort));
        }

        return match u32::from_be_bytes(buf[0..4].try_into().unwrap()) {
            0x00000001 => Ok(Self::Aes256Gcm),
            _          => Err(CertError::new(CertErrorCode::UnsupportedAlgorithm)),
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
pub enum SignAlgorithm {
    Ed25519 = 0x00000001,
}

impl SignAlgorithm {

    pub const BYTES_LEN: usize = 4;

    pub fn priv_key_len(&self) -> usize {
        return match self {
            Self::Ed25519 => Ed25519::PRIVATE_KEY_LEN,
        };
    }

    pub fn pub_key_len(&self) -> usize {
        return match self {
            Self::Ed25519 => Ed25519::PUBLIC_KEY_LEN,
        };
    }

    pub fn signature_len(&self) -> usize {
        return match self {
            Self::Ed25519 => Ed25519::SIGNATURE_LEN,
        };
    }

    pub fn from_bytes(buf: &[u8]) -> Result<Self, CertError> {

        if buf.len() < Self::BYTES_LEN {
            return Err(CertError::new(CertErrorCode::BufferTooShort));
        }

        return match u32::from_be_bytes(buf[0..4].try_into().unwrap()) {
            0x00000001 => Ok(Self::Ed25519),
            _          => Err(CertError::new(CertErrorCode::UnsupportedAlgorithm)),
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

    pub fn from_bytes(buf: &[u8]) -> Result<Self, CertError> {

        if buf.len() < Self::BYTES_LEN {
            return Err(CertError::new(CertErrorCode::BufferTooShort));
        }

        return match u16::from_be_bytes(buf[0..2].try_into().unwrap()) {
            0x0001 => Ok(Self::SubjectAuthOnly),
            _      => Err(CertError::new(CertErrorCode::UnsupportedCertificateType)),
        };

    }

    pub fn to_bytes(&self, buf: &mut [u8]) -> Result<usize, CertError> {

        if buf.len() < Self::BYTES_LEN {
            return Err(CertError::new(CertErrorCode::BufferTooShort));
        }

        buf[0..2].copy_from_slice(&(*self as u16).to_be_bytes());

        return Ok(Self::BYTES_LEN);

    }

}

pub struct CertificateEnvelope {
    aead_algo: AeadAlgorithm,
    aead_nonce: [u8; MAX_AEAD_NONCE_LEN],
    aead_payload_len: u16,
    aead_payload: Certificate,
    aead_tag: [u8; MAX_AEAD_TAG_LEN]
}

pub enum Certificate {
    SubjectAuthOnly(CertificateSubjectAuthOnly),
    // SubjectAuthAndSubjectSignKey(CertificateSubjectAuthAndSubjectSignKey)
}

pub struct CertificateSubjectAuthOnly {

    // --- input data for sign is from here ---
    common: CertificateCommonHeader, // .cert_type = CertificateType::CertificateSubjectAuthOnly
    sign_algo: SignAlgorithm,
    key_pair_id_len: u8,
    key_pair_id: Vec<u8>,
    random: [u8; 64],
    identity: IdentityFixedU64,
    validity_period: ValidityPeriodFixedU64Pair,
    // --- to here ---

    signature: [u8; MAX_SIGN_SIGNATURE_LEN]

}

impl CertificateSubjectAuthOnly {

    pub fn new(sign_algo: SignAlgorithm, priv_key: &[u8], key_pair_id: &[u8], identity: u64,
        not_before: u64, not_after: u64) -> Result<Self, CertError> {

        if sign_algo.priv_key_len() != priv_key.len() {
            return Err(CertError::new(CertErrorCode::BufferLengthIncorrect));
        }

        let len =
            CertificateCommonHeader::BYTES_LEN +
            SignAlgorithm::BYTES_LEN +
            1 +
            key_pair_id.len() +
            64 +
            IdentityFixedU64::BYTES_LEN +
            ValidityPeriodFixedU64Pair::BYTES_LEN +
            sign_algo.signature_len();

        let mut cert = Self{
            common: CertificateCommonHeader{
                cert_type: CertificateType::SubjectAuthOnly,
                length: len as u16,
            },
            sign_algo: sign_algo,
            key_pair_id_len: key_pair_id.len() as u8,
            key_pair_id: key_pair_id.to_vec(),
            random: [0; 64],
            identity: IdentityFixedU64{ inner: identity },
            validity_period: ValidityPeriodFixedU64Pair{
                not_before: not_before,
                not_after: not_after
            },
            signature: [0; MAX_SIGN_SIGNATURE_LEN]
        };

        let mut csprng = ChaCha20Rng::from_entropy();
        csprng.fill_bytes(&mut cert.random[..]);

        let mut buf = [0x00u8; 200];
        let b = cert.to_bytes(&mut buf[..]).unwrap() - sign_algo.signature_len();

        for t in &buf[..b] {
            print!("{:02x}", t);
        }
        println!();

        if let Err(_) = match sign_algo {
            SignAlgorithm::Ed25519 => Ed25519Signer::sign_oneshot(
                priv_key,
                &buf[..b],
                &mut cert.signature[..]
            ),
        } {
            return Err(CertError::new(CertErrorCode::SignFailed));
        }

        return Ok(cert);

    }

    pub fn verify(&self, pub_key: &[u8]) -> Result<bool, CertError> {

        if self.sign_algo.pub_key_len() != pub_key.len() {
            return Err(CertError::new(CertErrorCode::BufferLengthIncorrect));
        }

        let mut buf = [0x00u8; 200];
        let b = self.to_bytes(&mut buf[..]).unwrap() - self.sign_algo.signature_len();
        println!("{}", b);
        println!();
        for t in &buf[..b] {
            print!("{:02x}", t);
        }
        println!();

        return match self.sign_algo {
            SignAlgorithm::Ed25519 => Ed25519Verifier::verify_oneshot(
                pub_key,
                &buf[..b],
                &self.signature[..]
            ),
        }.map_err(|_| CertError::new(CertErrorCode::VerificationFailed));

    }

    pub fn from_bytes(buf: &[u8]) -> Result<Self, CertError> {

        let len =
            CertificateCommonHeader::BYTES_LEN +
            SignAlgorithm::BYTES_LEN +
            1 +
            64 +
            IdentityFixedU64::BYTES_LEN +
            ValidityPeriodFixedU64Pair::BYTES_LEN;
        if buf.len() < len {
            return Err(CertError::new(CertErrorCode::BufferTooShort));
        }

        let sign_algo = SignAlgorithm::from_bytes(&buf[CertificateCommonHeader::BYTES_LEN..])?;
        let key_pair_id_len =
            buf[CertificateCommonHeader::BYTES_LEN + SignAlgorithm::BYTES_LEN] as usize;
        let signature_len = sign_algo.signature_len();

        let len = len + key_pair_id_len + signature_len;
        if buf.len() < len {
            return Err(CertError::new(CertErrorCode::BufferTooShort));
        }

        let i1 = CertificateCommonHeader::BYTES_LEN + SignAlgorithm::BYTES_LEN + 1;
        let i2 = i1 + key_pair_id_len;
        let i3 = i2 + 64;
        let i4 = i3 + IdentityFixedU64::BYTES_LEN;
        let i5 = i4 + ValidityPeriodFixedU64Pair::BYTES_LEN;

        return Ok(Self{
            common: CertificateCommonHeader::from_bytes(&buf[..])?,
            sign_algo: sign_algo,
            key_pair_id_len: key_pair_id_len as u8,
            key_pair_id: buf[i1..i2].to_vec(),
            random: buf[i2..i3].try_into().unwrap(),
            identity: IdentityFixedU64::from_bytes(&buf[i3..])?,
            validity_period: ValidityPeriodFixedU64Pair::from_bytes(&buf[i4..])?,
            signature: buf[i5..(i5 + signature_len)].try_into().unwrap()
        });

    }

    pub fn to_bytes(&self, buf: &mut [u8]) -> Result<usize, CertError> {

        let len =
            CertificateCommonHeader::BYTES_LEN +
            SignAlgorithm::BYTES_LEN +
            1 +
            self.key_pair_id.len() +
            64 +
            IdentityFixedU64::BYTES_LEN +
            ValidityPeriodFixedU64Pair::BYTES_LEN +
            self.sign_algo.signature_len();

        if buf.len() < len {
            return Err(CertError::new(CertErrorCode::BufferTooShort));
        }

        self.common.to_bytes(&mut buf[..]).unwrap();
        self.sign_algo.to_bytes(&mut buf[CertificateCommonHeader::BYTES_LEN..]).unwrap();

        let i = CertificateCommonHeader::BYTES_LEN + SignAlgorithm::BYTES_LEN;
        buf[i] = self.key_pair_id.len() as u8;

        let i = i + 1;
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

struct CertificateCommonHeader {
    cert_type: CertificateType,
    length: u16, // length from self.cert_type to self.signature
}

impl CertificateCommonHeader {

    const BYTES_LEN: usize = CertificateType::BYTES_LEN + 2;

    fn from_bytes(buf: &[u8]) -> Result<Self, CertError> {

        if buf.len() < Self::BYTES_LEN {
            return Err(CertError::new(CertErrorCode::BufferTooShort));
        }

        return Ok(Self{
            cert_type: CertificateType::from_bytes(&buf[0..2])?,
            length: u16::from_be_bytes(buf[2..4].try_into().unwrap())
        });

    }

    fn to_bytes(&self, buf: &mut [u8]) -> Result<usize, CertError> {

        if buf.len() < Self::BYTES_LEN {
            return Err(CertError::new(CertErrorCode::BufferTooShort));
        }

        buf[0..2].copy_from_slice(&(self.cert_type as u16).to_be_bytes());
        buf[2..4].copy_from_slice(&self.length.to_be_bytes());

        return Ok(Self::BYTES_LEN);

    }

}

struct IdentityFixedU64 {
    inner: u64
}

impl IdentityFixedU64 {

    const BYTES_LEN: usize = 8;

    fn from_bytes(buf: &[u8]) -> Result<Self, CertError> {

        if buf.len() < Self::BYTES_LEN {
            return Err(CertError::new(CertErrorCode::BufferTooShort));
        }

        return Ok(Self{ inner: u64::from_be_bytes(buf[0..8].try_into().unwrap()) });

    }

    fn to_bytes(&self, buf: &mut [u8]) -> Result<usize, CertError> {

        if buf.len() < Self::BYTES_LEN {
            return Err(CertError::new(CertErrorCode::BufferTooShort));
        }

        buf[0..8].copy_from_slice(&self.inner.to_be_bytes());

        return Ok(Self::BYTES_LEN);

    }

}

struct ValidityPeriodFixedU64Pair {
    not_before: u64,
    not_after: u64
}

impl ValidityPeriodFixedU64Pair {

    const BYTES_LEN: usize = 16;

    fn from_bytes(buf: &[u8]) -> Result<Self, CertError> {

        if buf.len() < Self::BYTES_LEN {
            return Err(CertError::new(CertErrorCode::BufferTooShort));
        }

        return Ok(Self{
            not_before: u64::from_be_bytes(buf[0..8].try_into().unwrap()),
            not_after: u64::from_be_bytes(buf[8..16].try_into().unwrap())
        });

    }

    fn to_bytes(&self, buf: &mut [u8]) -> Result<usize, CertError> {

        if buf.len() < Self::BYTES_LEN {
            return Err(CertError::new(CertErrorCode::BufferTooShort));
        }

        buf[0..8].copy_from_slice(&self.not_before.to_be_bytes());
        buf[8..16].copy_from_slice(&self.not_after.to_be_bytes());

        return Ok(Self::BYTES_LEN);

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