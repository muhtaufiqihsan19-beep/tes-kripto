//! X25519 key agreement (RFC 7748), the classical half of both suites.

use aws_lc_rs::agreement::{self, UnparsedPublicKey, X25519};
use aws_lc_rs::encoding::{AsBigEndian, Curve25519SeedBin};
use zeroize::Zeroizing;

use super::Unspecified;

pub const KEY_LEN: usize = 32;

pub struct PrivateKey(agreement::PrivateKey);

impl PrivateKey {
    pub fn generate() -> Result<Self, Unspecified> {
        agreement::PrivateKey::generate(&X25519)
            .map(Self)
            .map_err(|_| Unspecified)
    }

    /// Rebuilds a key from its 32 stored bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Unspecified> {
        agreement::PrivateKey::from_private_key(&X25519, bytes)
            .map(Self)
            .map_err(|_| Unspecified)
    }

    /// The 32 bytes to store, accepted again by [`PrivateKey::from_bytes`].
    pub fn to_bytes(&self) -> Result<Zeroizing<[u8; KEY_LEN]>, Unspecified> {
        let seed: Curve25519SeedBin<'static> =
            AsBigEndian::<Curve25519SeedBin<'static>>::as_be_bytes(&self.0)
                .map_err(|_| Unspecified)?;
        let mut out = Zeroizing::new([0u8; KEY_LEN]);
        if seed.as_ref().len() != KEY_LEN {
            return Err(Unspecified);
        }
        out.copy_from_slice(seed.as_ref());
        Ok(out)
    }

    pub fn public_key(&self) -> Result<[u8; KEY_LEN], Unspecified> {
        let pk = self.0.compute_public_key().map_err(|_| Unspecified)?;
        <[u8; KEY_LEN]>::try_from(pk.as_ref()).map_err(|_| Unspecified)
    }

    /// Shared secret with `peer_public_key`. Rejects the all-zero output of a low-order
    /// point (RFC 7748, Section 6.1).
    pub fn agree(&self, peer_public_key: &[u8]) -> Result<Zeroizing<[u8; KEY_LEN]>, Unspecified> {
        let peer = UnparsedPublicKey::new(&X25519, peer_public_key);
        let ss = agreement::agree(&self.0, peer, Unspecified, |km| {
            let mut out = Zeroizing::new([0u8; KEY_LEN]);
            if km.len() != KEY_LEN {
                return Err(Unspecified);
            }
            out.copy_from_slice(km);
            Ok(out)
        })?;
        if ss.iter().all(|b| *b == 0) {
            return Err(Unspecified);
        }
        Ok(ss)
    }
}
