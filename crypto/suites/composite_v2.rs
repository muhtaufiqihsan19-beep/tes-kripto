//! Key-wrap suite v2: Composite ML-KEM (`id-MLKEM768-X25519-SHA3-256`) + HKDF-SHA256 + AES-256-KW.
//!
//! 1. **KEM**: the Composite ML-KEM construction of draft-ietf-lamps-pq-composite-kem
//!    (MLKEM768-X25519-SHA3-256): ML-KEM-768 encapsulation and an ephemeral X25519 exchange,
//!    combined as `SHA3-256(mlkemSS || tradSS || tradCT || tradPK || Label)`.
//!    Public key and ciphertext use the draft's encodings (ML-KEM part first).
//! 2. **KDF**: HKDF-SHA256 (RFC 5869) turns the composite shared secret into a 256-bit KEK.
//!    The `info` binds the suite label and the [`Context`] (document, version, position,
//!    key version), so a wrapped key only opens for the context it was made for.
//! 3. **Key wrap**: AES-256-KW (NIST SP 800-38F, RFC 3394) wraps the 32-byte DEK.
//!
//! The private key is stored expanded (`ML-KEM-768 dk || X25519 private key`) because
//! `aws-lc-rs` cannot derive an ML-KEM key pair from the 64-byte seed.

use zeroize::Zeroizing;

use super::{Context, CryptoError, KeyPair, PrivateKeyOps, SoftwareKey, Suite};
use crate::crypto::formats::append_lp;
use crate::crypto::primitives::{aes, hash, hkdf, mlkem, random, x25519};

pub const SUITE_ID: &str = "MLKEM768-X25519-SHA3-256-HKDFSHA256-AES256KW-v2";

/// Domain separator of `id-MLKEM768-X25519-SHA3-256` (hex `5c2e2f2f5e5c`, ASCII `\.//^\`).
pub const COMPOSITE_LABEL: &[u8] = b"\\.//^\\";
const KDF_LABEL: &[u8] =
    b"perisai-keyservice/keywrap/MLKEM768-X25519-SHA3-256-HKDFSHA256-AES256KW/v2";

const X25519_LEN: usize = x25519::KEY_LEN;
const MLKEM768_EK_LEN: usize = mlkem::EK_LEN;
const MLKEM768_DK_LEN: usize = mlkem::DK_LEN;
const MLKEM768_CT_LEN: usize = mlkem::CT_LEN;
const KW_OVERHEAD: usize = aes::KW_OVERHEAD;
pub const DEK_LEN: usize = random::DEK_LEN;
pub const SHARED_SECRET_LEN: usize = 32;

/// `ML-KEM-768 ek || X25519 public key`, as in the composite draft.
pub const PUBLIC_KEY_LEN: usize = MLKEM768_EK_LEN + X25519_LEN;
/// `ML-KEM-768 dk (expanded) || X25519 private key`.
pub const PRIVATE_KEY_LEN: usize = MLKEM768_DK_LEN + X25519_LEN;
/// `ML-KEM-768 ciphertext || X25519 ephemeral public key`, as in the composite draft.
pub const KEM_CIPHERTEXT_LEN: usize = MLKEM768_CT_LEN + X25519_LEN;
/// Composite ciphertext followed by the AES-256-KW output.
pub const WRAPPED_LEN: usize = KEM_CIPHERTEXT_LEN + DEK_LEN + KW_OVERHEAD;

pub struct CompositeV2;

fn internal<E>(_: E) -> CryptoError {
    CryptoError::Internal
}

/// The Composite ML-KEM combiner for `id-MLKEM768-X25519-SHA3-256`:
/// `SHA3-256(mlkemSS || tradSS || tradCT || tradPK || Label)`.
pub fn kem_combiner(
    mlkem_ss: &[u8],
    trad_ss: &[u8],
    trad_ct: &[u8],
    trad_pk: &[u8],
) -> Zeroizing<[u8; SHARED_SECRET_LEN]> {
    Zeroizing::new(hash::sha3_256_concat(&[
        mlkem_ss,
        trad_ss,
        trad_ct,
        trad_pk,
        COMPOSITE_LABEL,
    ]))
}

/// Composite ML-KEM decapsulation of a `KEM_CIPHERTEXT_LEN` ciphertext with a
/// `PRIVATE_KEY_LEN` private key. Public for the official known-answer tests.
pub fn decapsulate(
    private_key: &[u8],
    ciphertext: &[u8],
) -> Result<Zeroizing<[u8; SHARED_SECRET_LEN]>, CryptoError> {
    decapsulate_with(&software_key(private_key)?, ciphertext)
}

/// Composite ML-KEM decapsulation with a key reached through its operations.
fn decapsulate_with(
    key: &dyn PrivateKeyOps,
    ciphertext: &[u8],
) -> Result<Zeroizing<[u8; SHARED_SECRET_LEN]>, CryptoError> {
    if ciphertext.len() != KEM_CIPHERTEXT_LEN {
        return Err(CryptoError::Unwrap);
    }
    let (mlkem_ct, trad_ct) = ciphertext.split_at(MLKEM768_CT_LEN);
    let mlkem_ss = key.mlkem_decapsulate(mlkem_ct)?;
    let trad_ss = key.x25519_agree(trad_ct)?;
    Ok(kem_combiner(
        &mlkem_ss[..],
        &trad_ss[..],
        trad_ct,
        key.x25519_public_key(),
    ))
}

/// This suite's private key layout, `ML-KEM-768 dk || X25519 private key`.
fn software_key(private_key: &[u8]) -> Result<SoftwareKey<'_>, CryptoError> {
    if private_key.len() != PRIVATE_KEY_LEN {
        return Err(CryptoError::Unwrap);
    }
    let (dk, x_sk) = private_key.split_at(MLKEM768_DK_LEN);
    let ek = mlkem::ek_from_dk(dk).ok_or(CryptoError::Unwrap)?;
    SoftwareKey::new(dk, ek, x_sk)
}

/// Composite ML-KEM encapsulation to a `PUBLIC_KEY_LEN` public key.
fn encapsulate(
    public_key: &[u8],
) -> Result<(Vec<u8>, Zeroizing<[u8; SHARED_SECRET_LEN]>), CryptoError> {
    let (ek, trad_pk) = public_key.split_at(MLKEM768_EK_LEN);
    let (mlkem_ct, mlkem_ss) = mlkem::encapsulate(ek).map_err(|_| CryptoError::InvalidInput)?;

    let eph = x25519::PrivateKey::generate().map_err(internal)?;
    let trad_ct = eph.public_key().map_err(internal)?;
    let trad_ss = eph.agree(trad_pk).map_err(|_| CryptoError::InvalidInput)?;

    let ss = kem_combiner(&mlkem_ss[..], &trad_ss[..], &trad_ct, trad_pk);
    let mut ct = Vec::with_capacity(KEM_CIPHERTEXT_LEN);
    ct.extend_from_slice(&mlkem_ct);
    ct.extend_from_slice(&trad_ct);
    if ct.len() != KEM_CIPHERTEXT_LEN {
        return Err(CryptoError::Internal);
    }
    Ok((ct, ss))
}

fn derive_kek(ss: &[u8], ctx: &Context) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    let mut info = Vec::with_capacity(160);
    append_lp(&mut info, KDF_LABEL);
    append_lp(&mut info, &ctx.encode());
    hkdf::sha256_key(ss, &info).map_err(internal)
}

impl Suite for CompositeV2 {
    fn id(&self) -> &'static str {
        SUITE_ID
    }

    fn generate_key_pair(&self) -> Result<KeyPair, CryptoError> {
        let kem = mlkem::generate().map_err(internal)?;
        let x = x25519::PrivateKey::generate().map_err(internal)?;
        let x_pub = x.public_key().map_err(internal)?;
        let x_seed = x.to_bytes().map_err(internal)?;

        let public_key = self.public_key_from_parts(&kem.ek, &x_pub)?;
        let mut private_key = Zeroizing::new(Vec::with_capacity(PRIVATE_KEY_LEN));
        private_key.extend_from_slice(&kem.dk);
        private_key.extend_from_slice(&x_seed[..]);
        if private_key.len() != PRIVATE_KEY_LEN {
            return Err(CryptoError::Internal);
        }
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
        public_key.extend_from_slice(mlkem_ek);
        public_key.extend_from_slice(x25519_public_key);
        Ok(public_key)
    }

    fn wrap(&self, public_key: &[u8], dek: &[u8], ctx: &Context) -> Result<Vec<u8>, CryptoError> {
        if public_key.len() != PUBLIC_KEY_LEN || dek.len() != DEK_LEN {
            return Err(CryptoError::InvalidInput);
        }
        ctx.validate()?;
        let (kem_ct, ss) = encapsulate(public_key)?;
        let kek = derive_kek(&ss[..], ctx)?;
        let kw = aes::kw_wrap(&kek[..], dek).map_err(internal)?;
        if kw.len() != DEK_LEN + KW_OVERHEAD {
            return Err(CryptoError::Internal);
        }
        let mut out = Vec::with_capacity(WRAPPED_LEN);
        out.extend_from_slice(&kem_ct);
        out.extend_from_slice(&kw);
        Ok(out)
    }

    fn unwrap(
        &self,
        private_key: &[u8],
        wrapped: &[u8],
        ctx: &Context,
    ) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        self.unwrap_with(&software_key(private_key)?, wrapped, ctx)
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
        let (kem_ct, kw) = wrapped.split_at(KEM_CIPHERTEXT_LEN);
        let ss = decapsulate_with(key, kem_ct).map_err(|_| CryptoError::Unwrap)?;
        let kek = derive_kek(&ss[..], ctx).map_err(|_| CryptoError::Unwrap)?;
        let dek = aes::kw_unwrap(&kek[..], kw).map_err(|_| CryptoError::Unwrap)?;
        if dek.len() != DEK_LEN {
            return Err(CryptoError::Unwrap);
        }
        Ok(dek)
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
    fn label_matches_the_draft() {
        assert_eq!(COMPOSITE_LABEL, &[0x5c, 0x2e, 0x2f, 0x2f, 0x5e, 0x5c]);
    }

    #[test]
    fn sizes() {
        let kp = CompositeV2.generate_key_pair().unwrap();
        assert_eq!(kp.public_key.len(), PUBLIC_KEY_LEN);
        assert_eq!(kp.private_key.len(), PRIVATE_KEY_LEN);
        let w = CompositeV2.wrap(&kp.public_key, &dek(), &ctx()).unwrap();
        assert_eq!(w.len(), WRAPPED_LEN);
        assert_eq!(WRAPPED_LEN, 1088 + 32 + 40);
    }

    #[test]
    fn round_trip_and_randomized() {
        let kp = CompositeV2.generate_key_pair().unwrap();
        let d = dek();
        let w1 = CompositeV2.wrap(&kp.public_key, &d, &ctx()).unwrap();
        let w2 = CompositeV2.wrap(&kp.public_key, &d, &ctx()).unwrap();
        assert_ne!(w1, w2, "wrapping must be randomized");
        for w in [&w1, &w2] {
            assert_eq!(
                &CompositeV2.unwrap(&kp.private_key, w, &ctx()).unwrap()[..],
                &d[..]
            );
        }
    }

    #[test]
    fn decapsulate_matches_encapsulate() {
        let kp = CompositeV2.generate_key_pair().unwrap();
        let (ct, ss) = encapsulate(&kp.public_key).unwrap();
        assert_eq!(decapsulate(&kp.private_key, &ct).unwrap()[..], ss[..]);
    }

    type Mutation = (&'static str, Box<dyn Fn(&mut Context)>);

    #[test]
    fn context_binding() {
        let kp = CompositeV2.generate_key_pair().unwrap();
        let w = CompositeV2.wrap(&kp.public_key, &dek(), &ctx()).unwrap();
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
                CompositeV2.unwrap(&kp.private_key, &w, &c).unwrap_err(),
                CryptoError::Unwrap,
                "{name}"
            );
        }
    }

    #[test]
    fn wrong_private_key() {
        let a = CompositeV2.generate_key_pair().unwrap();
        let b = CompositeV2.generate_key_pair().unwrap();
        let w = CompositeV2.wrap(&a.public_key, &dek(), &ctx()).unwrap();
        assert!(CompositeV2.unwrap(&b.private_key, &w, &ctx()).is_err());
    }

    #[test]
    fn tamper_every_region() {
        let kp = CompositeV2.generate_key_pair().unwrap();
        let w = CompositeV2.wrap(&kp.public_key, &dek(), &ctx()).unwrap();
        for pos in [
            0,
            500,
            MLKEM768_CT_LEN - 1,
            MLKEM768_CT_LEN,
            KEM_CIPHERTEXT_LEN - 1,
            KEM_CIPHERTEXT_LEN,
            w.len() - 9,
            w.len() - 1,
        ] {
            let mut bad = w.clone();
            bad[pos] ^= 0x01;
            assert!(
                CompositeV2.unwrap(&kp.private_key, &bad, &ctx()).is_err(),
                "byte {pos}"
            );
        }
        assert!(
            CompositeV2
                .unwrap(&kp.private_key, &w[..w.len() - 1], &ctx())
                .is_err()
        );
    }

    #[test]
    fn invalid_inputs() {
        let kp = CompositeV2.generate_key_pair().unwrap();
        assert!(
            CompositeV2
                .wrap(&kp.public_key, &[0u8; 16], &ctx())
                .is_err()
        );
        assert!(
            CompositeV2
                .wrap(&kp.public_key[..10], &dek(), &ctx())
                .is_err()
        );
        let empty = Context {
            document_id: String::new(),
            version: 0,
            position_code: String::new(),
            key_version: 0,
        };
        assert!(CompositeV2.wrap(&kp.public_key, &dek(), &empty).is_err());
    }

    #[test]
    fn low_order_x25519_point_rejected() {
        let kp = CompositeV2.generate_key_pair().unwrap();
        let mut bad = kp.public_key.clone();
        bad[MLKEM768_EK_LEN..].fill(0);
        assert!(CompositeV2.wrap(&bad, &dek(), &ctx()).is_err());
    }

    #[test]
    fn v1_material_rejected() {
        use super::super::hybrid_v1::HybridV1;
        let v1 = HybridV1.generate_key_pair().unwrap();
        assert!(CompositeV2.wrap(&v1.public_key, &dek(), &ctx()).is_err());
        let v2 = CompositeV2.generate_key_pair().unwrap();
        let w = HybridV1.wrap(&v1.public_key, &dek(), &ctx()).unwrap();
        assert!(CompositeV2.unwrap(&v2.private_key, &w, &ctx()).is_err());
    }
}
