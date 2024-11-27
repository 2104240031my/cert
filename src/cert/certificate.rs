
enum HashAlgorithm: u32 {
    SHA3_256 = 0x00000001,
}

enum MacAlgorithm: u32 {
    HMAC_SHA3_256 = 0x00000001,
}

enum SignAlgorithm: u32 {
    Ed25519 = 0x00000001,
}

enum KdfAlgorithm: u32 {
}

enum CertificateEnvelopeType: u8 {
    Basic = 0x01,
}

enum CertificateType: u8 {
    SubjectAuthOnly              = 0x01,
    SubjectAuthAndSubjectSignKey = 0x02,
}

enum CertificateBody {
    SubjectAuthOnly(CertificateBodySubjectAuthOnly),
    SubjectAuthAndSubjectSignKey(CertificateBodySubjectAuthAndSubjectSignKey),
}

enum IdentityType: u8 {
    FixedU64 = 0x01,
}

enum Identity {
    FixedU64(u64)
}

impl Identity {

    fn len(&self) -> usize {
        return match self {
            Identity(_) => 8,
        };
    }

}

enum ValidityPeriodType: u8 {
    FixedU64Pair = 0x01,
}

enum ValidityPeriod {
    FixedU64Pair(struct {
        not_before: u64,
        not_after: u64
    })
}

impl ValidityPeriod {

    fn len(&self) -> usize {
        return match self {
            FixedU64Pair(_) => 16,
        };
    }

}

struct CertificateEnvelope {
    Basic(CertificateEnvelopeBasic),
}

struct CertificateEnvelopeBasic {
    aead_algo: AeadAlgorithm,
    aead_nonce: [u8; BUFFER_SIZE], // lengthはAeadAlgorithmに紐づけ
    aead_payload_len: u16,
    aead_payload: Certificate,
    aead_tag: [u8; BUFFER_SIZE] // lengthはAeadAlgorithmに紐づけ
}

// どうせQRコードには3000bytesぐらいしか入らんから、lenは大きくてもu16でいい
struct Certificate {
    cert_type: CertificateType,
    cert_body_len: u16,
    cert_body: CertificateBody
}

struct CertificateBodySubjectAuthOnly {
    sign_to: struct {
        sign_algo: SignAlgorithm,
        signer_key_pair_id: &[u8],
        random: [u8; 64],
        identity: Identity,
        validity_period: ValidityPeriod,
    },
    signature: [u8; BUFFER_SIZE] // lengthはSignAlgorithmに紐づけ
}

struct CertificateBodySubjectAuthAndSubjectSignKey {
    sign_to: struct {
        sign_algo: SignAlgorithm,
        signer_key_pair_id_len: u16,
        signer_key_pair_id: [u8; BUFFER_SIZE],
        random: [u8; 64],
        identity_type: IdentityType,
        identity: Identity,
        validity_period_type: ValidityPeriodType,
        validity_period: ValidityPeriod,
        fingerprint_algo: HashAlgorithm,
        subject_sign_key_fingerprint: [u8; BUFFER_SIZE] // Hash(ContextString + subject_sign_key.aead_payload.sign_key)
        // ここで生のsignkeyじゃなくてfingerprintとすることで、利用者がいつでもパスワード（subject_sign_keyを暗号化するための）を変更可能になる。
    },
    signature: [u8; BUFFER_SIZE], // lengthはSignAlgorithmに紐づけ
    subject_sign_key_envelope: struct {
        length: u16,
        content: struct {
            aead_algo: AeadAlgorithm,
            kdf_algo: KdfAlgorithm, // KDFでnonceも導出、よってnonceは格納フィールドはない
            aead_payload: struct {
                sign_algo: SignAlgorithm,
                sign_key: [u8; BUFFER_SIZE]
            },
            aead_tag: [u8; BUFFER_SIZE] // lengthはAeadAlgorithmに紐づけ
        }
    }
}

const BUFFER_SIZE: usize = 256;

impl CertificateEnvelope {

    pub fn seal_and_serialize(key: &[u8], nonce: &[u8], ) -> Vec<u8> {

        return match self.aead_algo {
            AeadAlgorithm::AES_256_CTR_HMAC_SHA3_256 => {
                let mut bytes: Vec<u8> = Vec::<u8>::with_capacity(
                    1 + Aes256CtrHmacSha3256::NONCE_LEN + 2 + self.aead_payload.len() + Aes256CtrHmacSha3256::MAC_LEN
                );
                self.aead_payload.serialize_into(bytes);
                Aes256CtrHmacSha3256::new(key)?.encrypt_and_generate()?;
                bytes
            },
        }

    }

}

impl Certificate {

    pub fn new(cert_type: CertificateType, cert_body: CertificateBody) -> Self {
        return Ok(Self{
            cert_type: cert_type,
            cert_body: cert_body
        });
    }

    pub fn len(&self) -> usize {
        return 1 + 2 + self.cert_body.len();
    }

    pub fn serialize_into() -> {



    }

}

impl CertificateBody {

    pub fn len(&self) -> usize {
        return match self {
            SubjectAuthOnly(v) => v.len(),
            SubjectAuthAndSubjectSignKey(v) => v.len(),
        };
    }

}

impl CertificateBodySubjectAuthOnly {

    pub fn new(sign_algo: SignAlgorithm, signer_key_pair_id: &[u8], random: &[u8; 64],
        identity: Identity, validity_period: ValidityPeriod) -> Self {
        return Ok(Self{
            sign_algo: sign_algo,
            signer_key_pair_id: signer_key_pair_id,
            random: random,
            identity: identity,
            validity_period; validity_period
        });
    }

    pub fn len(&self) -> usize {
        return 1 + 2 + self.signer_key_pair_id.len() + 64 + 1 + self.identity.len() + 1 + self.validity_period.len();
    }

    pub fn serialize_into(&self, bytes: &[u8]) -> Result<&[u8], CertError> {

        bytes.push(self.sign_algo as u8);
        bytes[bytes.len()..(bytes.len() + 2)].copy_from_slice(&signer_key_pair_id.len().to_be_bytes()[..]);
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

        return Ok(());

    }

}