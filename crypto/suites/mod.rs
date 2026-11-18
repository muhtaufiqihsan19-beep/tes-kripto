//! Key-wrap suites: how a document's DEK is wrapped for one position's public key.
//!
//! A suite combines a KEM, a KDF and a key-wrap or AEAD step from [`super::primitives`].
//! Each recipient of a document gets its own wrapped copy of the DEK, made by the suite
//! of that recipient's key, so v1 and v2 positions can share a document.
//!
//! | File | Suite id | Status |
//! |---|---|---|
//! | `composite_v2.rs` | `MLKEM768-X25519-SHA3-256-HKDFSHA256-AES256KW-v2` | default for new keys |
//! | `hybrid_v1.rs` | `X25519-MLKEM768-HKDFSHA256-AES256GCM-v1` | kept to open existing keys |
//!
//! [`Context`] is the binding every wrap carries (document, version, position, key
//! version); [`Registry`] looks suites up by id; `private_key.rs` lets a suite use a
//! private key it cannot see (an HSM key). A new suite is one new file that implements
//! [`Suite`], plus one line in [`all`].

pub mod composite_v2;
pub mod hybrid_v1;
mod private_key;

use std::collections::BTreeMap;
use std::sync::Arc;

use thiserror::Error;
use zeroize::Zeroizing;

pub use composite_v2::CompositeV2;
pub use hybrid_v1::HybridV1;
pub use private_key::{PrivateKeyOps, SoftwareKey};

use super::formats::append_lp;

/// Longest document id or position code, in bytes.
pub const MAX_ID_LEN: usize = 255;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CryptoError {
    #[error("invalid input")]
    InvalidInput,
    #[error("invalid context")]
    InvalidContext,
    #[error("unwrap failed")]
    Unwrap,
    #[error("unknown suite_id: {0}")]
    UnknownSuite(String),
    #[error("internal crypto failure")]
    Internal,
}

pub struct KeyPair {
    pub public_key: Vec<u8>,
    pub private_key: Zeroizing<Vec<u8>>,
}

/// Which position key: the position, its key version and the suite it was made with.
/// Stored inside the sealed private key (JKB1) and signed with the public key (PKS1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyIdentity {
    pub position_code: String,
    pub key_version: u32,
    pub suite_id: String,
}

/// One key-wrap algorithm. Implementations hold no state and no keys.
pub trait Suite: Send + Sync {
    /// The id stored next to every public key and wrapped key.
    fn id(&self) -> &'static str;
    /// A new position key pair, in this suite's byte layout.
    fn generate_key_pair(&self) -> Result<KeyPair, CryptoError>;
    /// Wraps `dek` for `public_key`, bound to `ctx`. Randomized: two calls differ.
    fn wrap(&self, public_key: &[u8], dek: &[u8], ctx: &Context) -> Result<Vec<u8>, CryptoError>;
    /// Opens a wrapped DEK with a private key in this suite's byte layout. Any mismatch
    /// (key, context, tampering) is [`CryptoError::Unwrap`].
    fn unwrap(
        &self,
        private_key: &[u8],
        wrapped: &[u8],
        ctx: &Context,
    ) -> Result<Zeroizing<Vec<u8>>, CryptoError>;
    /// Like [`Suite::unwrap`], with a private key that is only reachable through its
    /// operations (an HSM key). `unwrap` is this with a [`SoftwareKey`].
    fn unwrap_with(
        &self,
        key: &dyn PrivateKeyOps,
        wrapped: &[u8],
        ctx: &Context,
    ) -> Result<Zeroizing<Vec<u8>>, CryptoError>;
    /// This suite's public key layout from its two parts, for keys generated elsewhere.
    fn public_key_from_parts(
        &self,
        mlkem_ek: &[u8],
        x25519_public_key: &[u8],
    ) -> Result<Vec<u8>, CryptoError>;
}

/// Every suite this service can use. Older suites stay registered so that keys and
/// documents made with them can still be opened; `KS_DEFAULT_SUITE` picks the one used
/// for new position keys.
pub fn all() -> Vec<Arc<dyn Suite>> {
    vec![Arc::new(HybridV1), Arc::new(CompositeV2)]
}

/// Suites by id, and which one new position keys use.
pub struct Registry {
    suites: BTreeMap<&'static str, Arc<dyn Suite>>,
    default_id: &'static str,
}

impl Registry {
    pub fn new(suites: Vec<Arc<dyn Suite>>, default_id: &str) -> Result<Self, CryptoError> {
        let suites: BTreeMap<_, _> = suites.into_iter().map(|s| (s.id(), s)).collect();
        let default_id = suites
            .keys()
            .copied()
            .find(|id| *id == default_id)
            .ok_or_else(|| CryptoError::UnknownSuite(default_id.to_string()))?;
        Ok(Self { suites, default_id })
    }

    pub fn lookup(&self, id: &str) -> Result<Arc<dyn Suite>, CryptoError> {
        self.suites
            .get(id)
            .cloned()
            .ok_or_else(|| CryptoError::UnknownSuite(id.to_string()))
    }

    pub fn default_suite(&self) -> Arc<dyn Suite> {
        self.suites[self.default_id].clone()
    }

    pub fn ids(&self) -> Vec<&'static str> {
        self.suites.keys().copied().collect()
    }
}

const CONTEXT_LABEL: &[u8] = b"perisai-keyservice/context/v1";

/// The context a wrapped DEK is bound to. It goes into the KDF (and, for v1, the AEAD
/// associated data), so a wrapped key only opens for the document version and position
/// key it was made for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Context {
    pub document_id: String,
    pub version: u32,
    pub position_code: String,
    pub key_version: u32,
}

impl Context {
    pub fn validate(&self) -> Result<(), CryptoError> {
        let ok = |s: &str| !s.is_empty() && s.len() <= MAX_ID_LEN;
        if !ok(&self.document_id)
            || !ok(&self.position_code)
            || self.version == 0
            || self.key_version == 0
        {
            return Err(CryptoError::InvalidContext);
        }
        Ok(())
    }

    /// Unambiguous encoding (length-prefixed fields), pinned by the golden vectors.
    pub fn encode(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(64 + self.document_id.len() + self.position_code.len());
        append_lp(&mut b, CONTEXT_LABEL);
        append_lp(&mut b, self.document_id.as_bytes());
        b.extend_from_slice(&self.version.to_be_bytes());
        append_lp(&mut b, self.position_code.as_bytes());
        b.extend_from_slice(&self.key_version.to_be_bytes());
        b
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx(document_id: &str, position_code: &str) -> Context {
        Context {
            document_id: document_id.into(),
            version: 1,
            position_code: position_code.into(),
            key_version: 1,
        }
    }

    #[test]
    fn encode_is_unambiguous() {
        assert_ne!(ctx("AB", "C").encode(), ctx("A", "BC").encode());
    }

    #[test]
    fn validate_rejects_empty() {
        assert_eq!(ctx("", "X").validate(), Err(CryptoError::InvalidContext));
    }
}
