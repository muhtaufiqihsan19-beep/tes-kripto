//! ML-KEM-768 (FIPS 203), the post-quantum key encapsulation mechanism.

use aws_lc_rs::kem::{Ciphertext, DecapsulationKey, EncapsulationKey, ML_KEM_768};
use zeroize::Zeroizing;

use super::Unspecified;

/// Encapsulation (public) key.
pub const EK_LEN: usize = 1184;
/// Decapsulation (private) key, expanded form. `aws-lc-rs` cannot rebuild a key pair
/// from the 64-byte seed, so the expanded key is what gets stored.
pub const DK_LEN: usize = 2400;
pub const CT_LEN: usize = 1088;
pub const SS_LEN: usize = 32;

pub struct KeyPair {
    pub ek: Vec<u8>,
    pub dk: Zeroizing<Vec<u8>>,
}

/// The encapsulation key inside an expanded decapsulation key
/// (FIPS 203: `dk = dk_PKE (1152 bytes) || ek || H(ek) || z`).
pub fn ek_from_dk(dk: &[u8]) -> Option<&[u8]> {
    const DK_PKE_LEN: usize = 1152;
    (dk.len() == DK_LEN).then(|| &dk[DK_PKE_LEN..DK_PKE_LEN + EK_LEN])
}

pub fn generate() -> Result<KeyPair, Unspecified> {
    let dk = DecapsulationKey::generate(&ML_KEM_768).map_err(|_| Unspecified)?;
    let ek = dk
        .encapsulation_key()
        .and_then(|ek| ek.key_bytes())
        .map_err(|_| Unspecified)?;
    let dk = dk.key_bytes().map_err(|_| Unspecified)?;
    if ek.as_ref().len() != EK_LEN || dk.as_ref().len() != DK_LEN {
        return Err(Unspecified);
    }
    Ok(KeyPair {
        ek: ek.as_ref().to_vec(),
        dk: Zeroizing::new(dk.as_ref().to_vec()),
    })
}

/// Encapsulates to `ek`: returns `(ciphertext, shared secret)`. Fails for a malformed
/// key or one that fails the FIPS 203 modulus check.
pub fn encapsulate(ek: &[u8]) -> Result<(Vec<u8>, Zeroizing<[u8; SS_LEN]>), Unspecified> {
    let ek = EncapsulationKey::new(&ML_KEM_768, ek).map_err(|_| Unspecified)?;
    let (ct, ss) = ek.encapsulate().map_err(|_| Unspecified)?;
    Ok((ct.as_ref().to_vec(), secret(ss.as_ref())?))
}

/// Decapsulates `ct` with `dk`. A changed ciphertext gives a different, unrelated secret
/// (implicit rejection); only a malformed key or ciphertext length fails.
pub fn decapsulate(dk: &[u8], ct: &[u8]) -> Result<Zeroizing<[u8; SS_LEN]>, Unspecified> {
    let dk = DecapsulationKey::new(&ML_KEM_768, dk).map_err(|_| Unspecified)?;
    let ss = dk
        .decapsulate(Ciphertext::from(ct))
        .map_err(|_| Unspecified)?;
    secret(ss.as_ref())
}

fn secret(ss: &[u8]) -> Result<Zeroizing<[u8; SS_LEN]>, Unspecified> {
    let mut out = Zeroizing::new([0u8; SS_LEN]);
    if ss.len() != SS_LEN {
        return Err(Unspecified);
    }
    out.copy_from_slice(ss);
    Ok(out)
}
