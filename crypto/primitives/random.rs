//! Random bytes from the AWS-LC DRBG (CTR-DRBG seeded from the OS).

use aws_lc_rs::rand;
use zeroize::Zeroizing;

use super::Unspecified;

/// Length of a data encryption key (DEK): 256 bits.
pub const DEK_LEN: usize = 32;

/// Fills `dest` with random bytes.
pub fn fill(dest: &mut [u8]) -> Result<(), Unspecified> {
    rand::fill(dest).map_err(|_| Unspecified)
}

/// `N` random bytes, for public values such as nonces and identifiers.
pub fn bytes<const N: usize>() -> Result<[u8; N], Unspecified> {
    let mut b = [0u8; N];
    fill(&mut b)?;
    Ok(b)
}

/// A fresh data encryption key. Each document version gets its own.
pub fn dek() -> Result<Zeroizing<[u8; DEK_LEN]>, Unspecified> {
    let mut k = Zeroizing::new([0u8; DEK_LEN]);
    fill(&mut k[..])?;
    Ok(k)
}
