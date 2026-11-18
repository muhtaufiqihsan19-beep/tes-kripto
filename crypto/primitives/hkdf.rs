//! HKDF-SHA256 (RFC 5869).

use aws_lc_rs::hkdf;
use zeroize::Zeroizing;

use super::Unspecified;

struct Len(usize);

impl hkdf::KeyType for Len {
    fn len(&self) -> usize {
        self.0
    }
}

/// Extract with `salt`, then expand with `info` to fill `out`. Fails if `out` is longer
/// than 255 hash blocks (8160 bytes), as RFC 5869 requires.
pub fn sha256(salt: &[u8], ikm: &[u8], info: &[u8], out: &mut [u8]) -> Result<(), Unspecified> {
    let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, salt).extract(ikm);
    let info = [info];
    prk.expand(&info, Len(out.len()))
        .and_then(|okm| okm.fill(out))
        .map_err(|_| Unspecified)
}

/// A 256-bit key from HKDF-SHA256 with an empty salt (the key-wrap suites' KEK).
pub fn sha256_key(ikm: &[u8], info: &[u8]) -> Result<Zeroizing<[u8; 32]>, Unspecified> {
    let mut key = Zeroizing::new([0u8; 32]);
    sha256(&[], ikm, info, &mut key[..])?;
    Ok(key)
}
