//! Cryptography, in three layers. Each layer only uses the one below it.
//!
//! 1. [`primitives`]: one file per algorithm, the only code that calls `aws-lc-rs`.
//! 2. [`suites`]: key-wrap suites that wrap a document's DEK for a position's public key
//!    (`hybrid_v1`, `composite_v2`).
//! 3. [`eks1`]: the document ciphertext format, chunked AES-256-GCM under the DEK.
//!
//! [`formats`] holds the other binary formats (JKB1, PKS1, CTS1), so every byte layout
//! that leaves the service is in this folder. Nothing here talks to the network, stores
//! keys or knows about HTTP.

pub mod eks1;
pub mod formats;
pub mod primitives;
pub mod suites;

pub use suites::composite_v2::SUITE_ID as COMPOSITE_V2;
pub use suites::hybrid_v1::SUITE_ID as HYBRID_V1;
pub use suites::{
    CompositeV2, Context, CryptoError, HybridV1, KeyIdentity, KeyPair, MAX_ID_LEN, Registry, Suite,
};

/// A registry of every suite, with `default_id` used for new position keys.
pub fn registry(default_id: &str) -> Result<Registry, CryptoError> {
    Registry::new(suites::all(), default_id)
}
