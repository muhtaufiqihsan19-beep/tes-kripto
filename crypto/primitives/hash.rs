//! Hash functions: SHA-256 (FIPS 180-4) and SHA3-256 (FIPS 202).

use aws_lc_rs::digest;

/// Output length of both hashes.
pub const LEN: usize = 32;

pub fn sha256(data: &[u8]) -> [u8; LEN] {
    finish(digest::digest(&digest::SHA256, data))
}

pub fn sha3_256(data: &[u8]) -> [u8; LEN] {
    finish(digest::digest(&digest::SHA3_256, data))
}

/// SHA3-256 of the concatenation of `parts`, without building the concatenation.
pub fn sha3_256_concat(parts: &[&[u8]]) -> [u8; LEN] {
    let mut ctx = digest::Context::new(&digest::SHA3_256);
    for part in parts {
        ctx.update(part);
    }
    finish(ctx.finish())
}

fn finish(d: digest::Digest) -> [u8; LEN] {
    let mut out = [0u8; LEN];
    out.copy_from_slice(d.as_ref());
    out
}
