//! Key-wrap suite v1: X25519 + ML-KEM-768, HKDF-SHA256, AES-256-GCM.
//!
//! Kept so that position keys and documents made before v2 still open. New keys use
//! [`super::composite_v2`] unless `KS_DEFAULT_SUITE` says otherwise.
//!
//! - Public key: `X25519 public || ML-KEM-768 ek` (1216 bytes).
//! - Private key: `X25519 private || ML-KEM-768 ek || ML-KEM-768 dk` (3616 bytes).
//! - Wrapped key: `ephemeral X25519 public || ML-KEM ciphertext || nonce || AES-GCM(DEK) || tag`.
//! - KEK: HKDF-SHA256 over `mlkemSS || x25519SS`, `info` binds the label, both public
//!   values, the ciphertext and the [`Context`]; the context is also the GCM AAD.

use zeroize::Zeroizing;

use super::{Context, CryptoError, KeyPair, PrivateKeyOps, SoftwareKey, Suite};
use crate::crypto::formats::append_lp;
use crate::crypto::primitives::aes::{self, Aes256Gcm};
use crate::crypto::primitives::{hash, hkdf, mlkem, random, x25519};

pub const SUITE_ID: &str = "X25519-MLKEM768-HKDFSHA256-AES256GCM-v1";
const LABEL: &[u8] = b"perisai-keyservice/keywrap/X25519-MLKEM768-HKDFSHA256-AES256GCM/v1";

const X25519_LEN: usize = x25519::KEY_LEN;
const MLKEM768_EK_LEN: usize = mlkem::EK_LEN;
const MLKEM768_DK_LEN: usize = mlkem::DK_LEN;
const MLKEM768_CT_LEN: usize = mlkem::CT_LEN;
const NONCE_LEN: usize = aes::NONCE_LEN;
const TAG_LEN: usize = aes::TAG_LEN;
pub const DEK_LEN: usize = random::DEK_LEN;

pub const PUBLIC_KEY_LEN: usize = X25519_LEN + MLKEM768_EK_LEN;
pub const PRIVATE_KEY_LEN: usize = X25519_LEN + MLKEM768_EK_LEN + MLKEM768_DK_LEN;
pub const WRAPPED_LEN: usize = X25519_LEN + MLKEM768_CT_LEN + NONCE_LEN + DEK_LEN + TAG_LEN;

pub struct HybridV1;

fn internal<E>(_: E) -> CryptoError {
    CryptoError::Internal
}

fn unwrap_err<E>(_: E) -> CryptoError {
    CryptoError::Unwrap
}

fn derive_kek(
    ss_m: &[u8],
    ss_x: &[u8],
    eph_pub: &[u8],
    recipient_pub: &[u8],
    kem_ct: &[u8],
    ctx_bytes: &[u8],
) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    let mut ikm = Zeroizing::new(Vec::with_capacity(ss_m.len() + ss_x.len()));
    ikm.extend_from_slice(ss_m);
    ikm.extend_from_slice(ss_x);

    let pub_hash = hash::sha256(recipient_pub);
    let mut info = Vec::with_capacity(256 + kem_ct.len() + ctx_bytes.len());
    append_lp(&mut info, LABEL);
    append_lp(&mut info, eph_pub);
    append_lp(&mut info, &recipient_pub[..X25519_LEN]);
    append_lp(&mut info, &pub_hash);
    append_lp(&mut info, kem_ct);
    append_lp(&mut info, ctx_bytes);

    hkdf::sha256_key(&ikm, &info).map_err(internal)
}

impl Suite for HybridV1 {
    fn id(&self) -> &'static str {
        SUITE_ID
    }

    fn generate_key_pair(&self) -> Result<KeyPair, CryptoError> {
        let x = x25519::PrivateKey::generate().map_err(internal)?;
        let x_pub = x.public_key().map_err(internal)?;
        let x_seed = x.to_bytes().map_err(internal)?;
        let kem = mlkem::generate().map_err(internal)?;

        let public_key = self.public_key_from_parts(&kem.ek, &x_pub)?;
        let mut private_key = Zeroizing::new(Vec::with_capacity(PRIVATE_KEY_LEN));
        private_key.extend_from_slice(&x_seed[..]);
        private_key.extend_from_slice(&kem.ek);
        private_key.extend_from_slice(&kem.dk);
        Ok(KeyPair {
            public_key,
            private_key,
        })
    }

    fn public_key_from_parts(
        &self,
        mlkem_ek: &[u8],
        x25519_public_key: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        if mlkem_ek.len() != MLKEM768_EK_LEN || x25519_public_key.len() != X25519_LEN {
            return Err(CryptoError::InvalidInput);
        }
        let mut public_key = Vec::with_capacity(PUBLIC_KEY_LEN);
        public_key.extend_from_slice(x25519_public_key);
        public_key.extend_from_slice(mlkem_ek);
        Ok(public_key)
    }

    fn wrap(&self, public_key: &[u8], dek: &[u8], ctx: &Context) -> Result<Vec<u8>, CryptoError> {
        if public_key.len() != PUBLIC_KEY_LEN || dek.len() != DEK_LEN {
            return Err(CryptoError::InvalidInput);
        }
        ctx.validate()?;
        let (recipient_x, recipient_ek) = public_key.split_at(X25519_LEN);

        let eph = x25519::PrivateKey::generate().map_err(internal)?;
        let eph_pub = eph.public_key().map_err(internal)?;
        let ss_x = eph
            .agree(recipient_x)
            .map_err(|_| CryptoError::InvalidInput)?;
        let (kem_ct, ss_m) =
            mlkem::encapsulate(recipient_ek).map_err(|_| CryptoError::InvalidInput)?;

        let ctx_bytes = ctx.encode();
        let kek = derive_kek(
            &ss_m[..],
            &ss_x[..],
            &eph_pub,
            public_key,
            &kem_ct,
            &ctx_bytes,
        )?;
        let key = Aes256Gcm::new(&kek[..]).map_err(internal)?;

        let nonce = random::bytes::<NONCE_LEN>().map_err(internal)?;
        let mut sealed = dek.to_vec();
        key.seal_append_tag(nonce, &ctx_bytes, &mut sealed)
            .map_err(internal)?;

        let mut out = Vec::with_capacity(WRAPPED_LEN);
        out.extend_from_slice(&eph_pub);
        out.extend_from_slice(&kem_ct);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&sealed);
        debug_assert_eq!(out.len(), WRAPPED_LEN);
        Ok(out)
    }

    fn unwrap(
        &self,
        private_key: &[u8],
        wrapped: &[u8],
        ctx: &Context,
    ) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        if private_key.len() != PRIVATE_KEY_LEN {
            return Err(CryptoError::Unwrap);
        }
        let (x_seed, rest) = private_key.split_at(X25519_LEN);
        let (ek, dk) = rest.split_at(MLKEM768_EK_LEN);
        let key = SoftwareKey::new(dk, ek, x_seed)?;
        self.unwrap_with(&key, wrapped, ctx)
    }

    fn unwrap_with(
        &self,
        key: &dyn PrivateKeyOps,
        wrapped: &[u8],
        ctx: &Context,
    ) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        if wrapped.len() != WRAPPED_LEN {
            return Err(CryptoError::Unwrap);
        }
        ctx.validate().map_err(|_| CryptoError::Unwrap)?;

        let (eph_pub, rest) = wrapped.split_at(X25519_LEN);
        let (kem_ct, rest) = rest.split_at(MLKEM768_CT_LEN);
        let (nonce, sealed) = rest.split_at(NONCE_LEN);

        let ss_x = key.x25519_agree(eph_pub).map_err(unwrap_err)?;
        let ss_m = key.mlkem_decapsulate(kem_ct).map_err(unwrap_err)?;
        let recipient_pub = self
            .public_key_from_parts(key.mlkem_public_key(), key.x25519_public_key())
            .map_err(unwrap_err)?;

        let ctx_bytes = ctx.encode();
        let kek = derive_kek(
            &ss_m[..],
            &ss_x[..],
            eph_pub,
            &recipient_pub,
            kem_ct,
            &ctx_bytes,
        )
        .map_err(unwrap_err)?;
        let aead = Aes256Gcm::new(&kek[..]).map_err(unwrap_err)?;

        let nonce: [u8; NONCE_LEN] = nonce.try_into().map_err(unwrap_err)?;
        let mut buf = Zeroizing::new(sealed.to_vec());
        let plain_len = aead
            .open(nonce, &ctx_bytes, &mut buf)
            .map_err(unwrap_err)?
            .len();
        if plain_len != DEK_LEN {
            return Err(CryptoError::Unwrap);
        }
        buf.truncate(plain_len);
        Ok(buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx() -> Context {
        Context {
            document_id: "ND-2026-0001".into(),
            version: 1,
            position_code: "HEAD-OF-BUREAU".into(),
            key_version: 1,
        }
    }

    fn dek() -> Vec<u8> {
        random::dek().unwrap().to_vec()
    }

    #[test]
    fn sizes() {
        let kp = HybridV1.generate_key_pair().unwrap();
        assert_eq!(kp.public_key.len(), PUBLIC_KEY_LEN);
        assert_eq!(kp.private_key.len(), PRIVATE_KEY_LEN);
        let w = HybridV1.wrap(&kp.public_key, &dek(), &ctx()).unwrap();
        assert_eq!(w.len(), WRAPPED_LEN);
    }

    #[test]
    fn round_trip_and_randomized() {
        let kp = HybridV1.generate_key_pair().unwrap();
        let d = dek();
        let w1 = HybridV1.wrap(&kp.public_key, &d, &ctx()).unwrap();
        let w2 = HybridV1.wrap(&kp.public_key, &d, &ctx()).unwrap();
        assert_ne!(w1, w2, "wrapping must be randomized");
        assert_eq!(
            &HybridV1.unwrap(&kp.private_key, &w1, &ctx()).unwrap()[..],
            &d[..]
        );
        assert_eq!(
            &HybridV1.unwrap(&kp.private_key, &w2, &ctx()).unwrap()[..],
            &d[..]
        );
    }

    type Mutation = (&'static str, Box<dyn Fn(&mut Context)>);

    #[test]
    fn context_binding() {
        let kp = HybridV1.generate_key_pair().unwrap();
        let w = HybridV1.wrap(&kp.public_key, &dek(), &ctx()).unwrap();
        let mutations: Vec<Mutation> = vec![
            (
                "other document",
                Box::new(|c: &mut Context| c.document_id = "ND-2026-0002".into()),
            ),
            ("other version", Box::new(|c: &mut Context| c.version = 2)),
            (
                "other position",
                Box::new(|c: &mut Context| c.position_code = "HEAD-OF-SECTION".into()),
            ),
            (
                "other key version",
                Box::new(|c: &mut Context| c.key_version = 2),
            ),
        ];
        for (name, m) in mutations {
            let mut c = ctx();
            m(&mut c);
            assert_eq!(
                HybridV1.unwrap(&kp.private_key, &w, &c).unwrap_err(),
                CryptoError::Unwrap,
                "{name}"
            );
        }
    }

    #[test]
    fn wrong_private_key() {
        let a = HybridV1.generate_key_pair().unwrap();
        let b = HybridV1.generate_key_pair().unwrap();
        let w = HybridV1.wrap(&a.public_key, &dek(), &ctx()).unwrap();
        assert!(HybridV1.unwrap(&b.private_key, &w, &ctx()).is_err());
    }

    #[test]
    fn tamper_every_region() {
        let kp = HybridV1.generate_key_pair().unwrap();
        let w = HybridV1.wrap(&kp.public_key, &dek(), &ctx()).unwrap();
        for pos in [
            0,
            5,
            31,
            32,
            100,
            600,
            X25519_LEN + MLKEM768_CT_LEN,
            w.len() - 17,
            w.len() - 1,
        ] {
            let mut bad = w.clone();
            bad[pos] ^= 0x01;
            assert!(
                HybridV1.unwrap(&kp.private_key, &bad, &ctx()).is_err(),
                "byte {pos}"
            );
        }
        assert!(
            HybridV1
                .unwrap(&kp.private_key, &w[..w.len() - 1], &ctx())
                .is_err()
        );
    }

    #[test]
    fn invalid_inputs() {
        let kp = HybridV1.generate_key_pair().unwrap();
        assert!(HybridV1.wrap(&kp.public_key, &[0u8; 16], &ctx()).is_err());
        assert!(HybridV1.wrap(&kp.public_key[..10], &dek(), &ctx()).is_err());
        let empty = Context {
            document_id: String::new(),
            version: 0,
            position_code: String::new(),
            key_version: 0,
        };
        assert!(HybridV1.wrap(&kp.public_key, &dek(), &empty).is_err());
    }

    #[test]
    fn low_order_x25519_point_rejected() {
        let kp = HybridV1.generate_key_pair().unwrap();
        let mut bad = kp.public_key.clone();
        bad[..X25519_LEN].fill(0);
        assert!(HybridV1.wrap(&bad, &dek(), &ctx()).is_err());
    }

    #[test]
    fn private_key_round_trips_through_bytes() {
        let kp = HybridV1.generate_key_pair().unwrap();
        let stored = kp.private_key.to_vec();
        let d = dek();
        let w = HybridV1.wrap(&kp.public_key, &d, &ctx()).unwrap();
        assert_eq!(&HybridV1.unwrap(&stored, &w, &ctx()).unwrap()[..], &d[..]);
    }
}
