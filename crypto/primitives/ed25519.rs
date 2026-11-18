//! Ed25519 signatures (RFC 8032).

use aws_lc_rs::signature::{ED25519, Ed25519KeyPair, KeyPair as _, UnparsedPublicKey};

use super::Unspecified;

pub const PUBLIC_KEY_LEN: usize = 32;
pub const SIGNATURE_LEN: usize = 64;

/// True if `signature` is a valid Ed25519 signature of `message` under `public_key`.
pub fn verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    UnparsedPublicKey::new(&ED25519, public_key)
        .verify(message, signature)
        .is_ok()
}

/// An in-memory signing key. Production signatures come from OpenBao Transit; this key is
/// for the dev signer and for tests.
pub struct SigningKey(Ed25519KeyPair);

impl SigningKey {
    pub fn generate() -> Result<Self, Unspecified> {
        Ed25519KeyPair::generate()
            .map(Self)
            .map_err(|_| Unspecified)
    }

    pub fn public_key(&self) -> [u8; PUBLIC_KEY_LEN] {
        self.0
            .public_key()
            .as_ref()
            .try_into()
            .expect("Ed25519 public keys are 32 bytes")
    }

    pub fn sign(&self, message: &[u8]) -> [u8; SIGNATURE_LEN] {
        self.0
            .sign(message)
            .as_ref()
            .try_into()
            .expect("Ed25519 signatures are 64 bytes")
    }
}
