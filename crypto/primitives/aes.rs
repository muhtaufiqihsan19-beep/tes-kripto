//! AES-256 in two modes: GCM (authenticated encryption, NIST SP 800-38D) and
//! Key Wrap (NIST SP 800-38F, RFC 3394).

use aws_lc_rs::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
use aws_lc_rs::key_wrap::{AES_256, AesKek, KeyWrap};
use zeroize::Zeroizing;

use super::Unspecified;

pub const KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 12;
pub const TAG_LEN: usize = 16;
/// AES-KW adds one 8-byte integrity block.
pub const KW_OVERHEAD: usize = 8;

/// An AES-256-GCM key. The caller supplies every nonce and must never reuse one with the
/// same key: EKS1 uses a random prefix plus the chunk index, the others a random nonce.
pub struct Aes256Gcm(LessSafeKey);

impl Aes256Gcm {
    /// Fails unless `key` is 32 bytes.
    pub fn new(key: &[u8]) -> Result<Self, Unspecified> {
        let key = UnboundKey::new(&AES_256_GCM, key).map_err(|_| Unspecified)?;
        Ok(Self(LessSafeKey::new(key)))
    }

    /// Encrypts `in_out` in place and appends the 16-byte tag.
    pub fn seal_append_tag(
        &self,
        nonce: [u8; NONCE_LEN],
        aad: &[u8],
        in_out: &mut Vec<u8>,
    ) -> Result<(), Unspecified> {
        self.0
            .seal_in_place_append_tag(Nonce::assume_unique_for_key(nonce), Aad::from(aad), in_out)
            .map_err(|_| Unspecified)
    }

    /// Encrypts `in_out` in place and returns the tag separately.
    pub fn seal_separate_tag(
        &self,
        nonce: [u8; NONCE_LEN],
        aad: &[u8],
        in_out: &mut [u8],
    ) -> Result<[u8; TAG_LEN], Unspecified> {
        let tag = self
            .0
            .seal_in_place_separate_tag(Nonce::assume_unique_for_key(nonce), Aad::from(aad), in_out)
            .map_err(|_| Unspecified)?;
        let mut out = [0u8; TAG_LEN];
        out.copy_from_slice(tag.as_ref());
        Ok(out)
    }

    /// Verifies and decrypts `ciphertext || tag` in place. Returns the plaintext part of
    /// `in_out`; on failure nothing is released.
    pub fn open<'b>(
        &self,
        nonce: [u8; NONCE_LEN],
        aad: &[u8],
        in_out: &'b mut [u8],
    ) -> Result<&'b mut [u8], Unspecified> {
        self.0
            .open_in_place(Nonce::assume_unique_for_key(nonce), Aad::from(aad), in_out)
            .map_err(|_| Unspecified)
    }
}

/// AES-256-KW: wraps `key_data` (a multiple of 8 bytes, at least 16) under `kek`.
pub fn kw_wrap(kek: &[u8], key_data: &[u8]) -> Result<Vec<u8>, Unspecified> {
    let kek = AesKek::new(&AES_256, kek).map_err(|_| Unspecified)?;
    let mut out = vec![0u8; key_data.len() + KW_OVERHEAD];
    let n = kek.wrap(key_data, &mut out).map_err(|_| Unspecified)?.len();
    out.truncate(n);
    Ok(out)
}

/// AES-256-KW unwrap. Fails if the integrity check does not hold.
pub fn kw_unwrap(kek: &[u8], wrapped: &[u8]) -> Result<Zeroizing<Vec<u8>>, Unspecified> {
    let kek = AesKek::new(&AES_256, kek).map_err(|_| Unspecified)?;
    let mut out = Zeroizing::new(vec![0u8; wrapped.len()]);
    let n = kek
        .unwrap(wrapped, &mut out)
        .map_err(|_| Unspecified)?
        .len();
    out.truncate(n);
    Ok(out)
}
