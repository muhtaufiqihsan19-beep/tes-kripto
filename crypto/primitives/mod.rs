//! Cryptographic primitives: one file per algorithm.
//!
//! This folder is the only code that calls `aws-lc-rs` directly
//! (`scripts/check-crypto-deps.sh` enforces it). Suites, EKS1, the backends and grant
//! verification compose these functions, so an audit of "which algorithm, which library"
//! starts and ends here, and the known-answer tests in `tests/kat.rs` run against these
//! wrappers rather than against the library.
//!
//! | File | Algorithm | Used for |
//! |---|---|---|
//! | `aes.rs` | AES-256-GCM, AES-256-KW (RFC 3394) | EKS1 chunks, v1 key wrap, dev sealer; v2 key wrap |
//! | `mlkem.rs` | ML-KEM-768 (FIPS 203) | post-quantum half of both suites |
//! | `x25519.rs` | X25519 (RFC 7748) | classical half of both suites |
//! | `hkdf.rs` | HKDF-SHA256 (RFC 5869) | KEK derivation in both suites |
//! | `hash.rs` | SHA-256, SHA3-256 (FIPS 180-4, FIPS 202) | signed messages, EKS1 AAD, v2 combiner |
//! | `ed25519.rs` | Ed25519 (RFC 8032) | grants, dev signer, OpenBao signature check |
//! | `random.rs` | AWS-LC DRBG | DEKs, nonces, request ids |

pub mod aes;
pub mod ed25519;
pub mod hash;
pub mod hkdf;
pub mod mlkem;
pub mod random;
pub mod x25519;

/// A primitive failed. Like `aws-lc-rs`' own error it carries no detail, so callers map it
/// to an error that fits their context (bad input, failed unwrap, internal).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("cryptographic operation failed")]
pub struct Unspecified;
