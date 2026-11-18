//! The private-key operations a suite needs, behind a trait, so the key itself can stay
//! in software (bytes in memory) or inside an HSM.
//!
//! Both suites open a wrapped DEK with exactly two private-key operations, ML-KEM-768
//! decapsulation and one X25519 agreement, plus the matching public halves for the KDF.
//! [`SoftwareKey`] does them from key bytes; an HSM adapter implements [`PrivateKeyOps`]
//! with the HSM's own operations (ML-KEM decapsulation, `CKM_ML_KEM` in PKCS#11 v3.2, and
//! an ECDH derive on its X25519 key) and passes it to [`super::Suite::unwrap_with`].

use zeroize::Zeroizing;

use super::CryptoError;
use crate::crypto::primitives::{mlkem, x25519};

/// What a suite asks of a position private key.
pub trait PrivateKeyOps: Send + Sync {
    /// ML-KEM-768 decapsulation of `ciphertext`.
    fn mlkem_decapsulate(&self, ciphertext: &[u8]) -> Result<Zeroizing<[u8; 32]>, CryptoError>;
    /// X25519 with `peer_public_key`. Must reject an all-zero result (RFC 7748, 6.1).
    fn x25519_agree(&self, peer_public_key: &[u8]) -> Result<Zeroizing<[u8; 32]>, CryptoError>;
    /// The ML-KEM-768 encapsulation key of this position (1184 bytes).
    fn mlkem_public_key(&self) -> &[u8];
    /// The X25519 public key of this position.
    fn x25519_public_key(&self) -> &[u8; x25519::KEY_LEN];
}

/// A private key held as bytes in this process (the software key custody).
pub struct SoftwareKey<'a> {
    mlkem_dk: &'a [u8],
    mlkem_ek: &'a [u8],
    x25519: x25519::PrivateKey,
    x25519_public: [u8; x25519::KEY_LEN],
}

impl<'a> SoftwareKey<'a> {
    /// `mlkem_dk` is the expanded 2400-byte key, `mlkem_ek` its 1184-byte public key and
    /// `x25519_private` the 32 stored bytes.
    pub fn new(
        mlkem_dk: &'a [u8],
        mlkem_ek: &'a [u8],
        x25519_private: &[u8],
    ) -> Result<Self, CryptoError> {
        if mlkem_dk.len() != mlkem::DK_LEN || mlkem_ek.len() != mlkem::EK_LEN {
            return Err(CryptoError::Unwrap);
        }
        let x25519 =
            x25519::PrivateKey::from_bytes(x25519_private).map_err(|_| CryptoError::Unwrap)?;
        let x25519_public = x25519.public_key().map_err(|_| CryptoError::Unwrap)?;
        Ok(Self {
            mlkem_dk,
            mlkem_ek,
            x25519,
            x25519_public,
        })
    }
}

impl PrivateKeyOps for SoftwareKey<'_> {
    fn mlkem_decapsulate(&self, ciphertext: &[u8]) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
        mlkem::decapsulate(self.mlkem_dk, ciphertext).map_err(|_| CryptoError::Unwrap)
    }

    fn x25519_agree(&self, peer_public_key: &[u8]) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
        self.x25519
            .agree(peer_public_key)
            .map_err(|_| CryptoError::Unwrap)
    }

    fn mlkem_public_key(&self) -> &[u8] {
        self.mlkem_ek
    }

    fn x25519_public_key(&self) -> &[u8; x25519::KEY_LEN] {
        &self.x25519_public
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::primitives::random;
    use crate::crypto::{CompositeV2, Context, HybridV1, Suite};

    /// Stands in for an HSM: the key parts live in this struct, and the suites only see
    /// them through `PrivateKeyOps`, the way they would see a key inside an HSM.
    struct ExternalKey {
        kem: mlkem::KeyPair,
        x: x25519::PrivateKey,
        x_public: [u8; 32],
    }

    impl ExternalKey {
        fn generate() -> Self {
            let x = x25519::PrivateKey::generate().unwrap();
            let x_public = x.public_key().unwrap();
            Self {
                kem: mlkem::generate().unwrap(),
                x,
                x_public,
            }
        }
    }

    impl PrivateKeyOps for ExternalKey {
        fn mlkem_decapsulate(&self, ct: &[u8]) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
            mlkem::decapsulate(&self.kem.dk, ct).map_err(|_| CryptoError::Unwrap)
        }
        fn x25519_agree(&self, peer: &[u8]) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
            self.x.agree(peer).map_err(|_| CryptoError::Unwrap)
        }
        fn mlkem_public_key(&self) -> &[u8] {
            &self.kem.ek
        }
        fn x25519_public_key(&self) -> &[u8; 32] {
            &self.x_public
        }
    }

    #[test]
    fn suites_work_with_an_external_key() {
        let ctx = Context {
            document_id: "DOC-1".into(),
            version: 1,
            position_code: "HEAD-OF-BUREAU".into(),
            key_version: 1,
        };
        for suite in [&HybridV1 as &dyn Suite, &CompositeV2] {
            let key = ExternalKey::generate();
            let public_key = suite
                .public_key_from_parts(key.mlkem_public_key(), key.x25519_public_key())
                .unwrap();
            let dek = random::dek().unwrap();
            let wrapped = suite.wrap(&public_key, &dek[..], &ctx).unwrap();
            let got = suite.unwrap_with(&key, &wrapped, &ctx).unwrap();
            assert_eq!(&got[..], &dek[..], "{}", suite.id());

            let other = ExternalKey::generate();
            assert!(suite.unwrap_with(&other, &wrapped, &ctx).is_err());
        }
    }
}
