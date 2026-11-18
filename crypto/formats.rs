//! Binary formats that leave this service: stored by E-Office, or signed and checked later.
//!
//! | Format | What it is |
//! |---|---|
//! | JKB1 | position private key envelope, sealed by a [`crate::backends::Sealer`] |
//! | PKS1 | position public key + service signature |
//! | CTS1 | EKS1 ciphertext + service signature |
//! | EKS1 | document ciphertext, in [`super::eks1`] together with its cipher |
//!
//! Every format is pinned by `tests/vectors/golden/*.json`. A change that breaks a golden
//! test breaks keys and documents that already exist.

use zeroize::Zeroizing;

use super::primitives::hash;
use super::suites::KeyIdentity;

/// Appends `data` with a 4-byte big-endian length prefix. All formats use this so that
/// no two different field lists encode to the same bytes.
pub fn append_lp(buf: &mut Vec<u8>, data: &[u8]) {
    let len = u32::try_from(data.len()).expect("field longer than 4 GiB");
    buf.extend_from_slice(&len.to_be_bytes());
    buf.extend_from_slice(data);
}

// ---------------------------------------------------------------------------------------
// JKB1: position private key envelope
// ---------------------------------------------------------------------------------------

const JKB1_MAGIC: &[u8; 4] = b"JKB1";

/// `"JKB1" || lp(suite_id) || lp(position_code) || key_version || lp(private_key)`.
/// The identity travels inside the sealed blob, so a blob swapped between positions or
/// key versions is detected after unsealing.
pub fn encode_jkb1(id: &KeyIdentity, private_key: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut b = Zeroizing::new(Vec::with_capacity(64 + private_key.len()));
    b.extend_from_slice(JKB1_MAGIC);
    append_lp(&mut b, id.suite_id.as_bytes());
    append_lp(&mut b, id.position_code.as_bytes());
    b.extend_from_slice(&id.key_version.to_be_bytes());
    append_lp(&mut b, private_key);
    b
}

/// The inverse of [`encode_jkb1`]; `None` for anything else, trailing bytes included.
pub fn decode_jkb1(mut b: &[u8]) -> Option<(KeyIdentity, Zeroizing<Vec<u8>>)> {
    fn take<'a>(b: &mut &'a [u8], n: usize) -> Option<&'a [u8]> {
        if b.len() < n {
            return None;
        }
        let (head, tail) = b.split_at(n);
        *b = tail;
        Some(head)
    }
    fn take_u32(b: &mut &[u8]) -> Option<u32> {
        Some(u32::from_be_bytes(take(b, 4)?.try_into().ok()?))
    }
    fn take_str(b: &mut &[u8]) -> Option<String> {
        let n = take_u32(b)? as usize;
        String::from_utf8(take(b, n)?.to_vec()).ok()
    }

    if take(&mut b, 4)? != JKB1_MAGIC {
        return None;
    }
    let suite_id = take_str(&mut b)?;
    let position_code = take_str(&mut b)?;
    let key_version = take_u32(&mut b)?;
    let n = take_u32(&mut b)? as usize;
    let private_key = Zeroizing::new(take(&mut b, n)?.to_vec());
    if !b.is_empty() {
        return None;
    }
    let identity = KeyIdentity {
        position_code,
        key_version,
        suite_id,
    };
    Some((identity, private_key))
}

// ---------------------------------------------------------------------------------------
// PKS1 and CTS1: signed envelopes, `magic || lp(signature) || body`
// ---------------------------------------------------------------------------------------

/// PKS1: a position public key signed by this service, so E-Office cannot be tricked
/// into encrypting for a key that this service never issued.
pub const PUBLIC_KEY_MAGIC: &[u8; 4] = b"PKS1";
/// CTS1: an EKS1 ciphertext signed by this service, checked before any key is opened.
pub const CIPHERTEXT_MAGIC: &[u8; 4] = b"CTS1";
const PUBLIC_KEY_LABEL: &[u8] = b"perisai-keyservice/public-key/v1";
const CIPHERTEXT_LABEL: &[u8] = b"perisai-keyservice/ciphertext/v1";
const MAX_SIGNATURE_LEN: usize = 512;

/// The bytes signed for a PKS1 public key.
pub fn public_key_message(
    suite_id: &str,
    position_code: &str,
    key_version: u32,
    public_key: &[u8],
) -> Vec<u8> {
    let mut m = Vec::with_capacity(64 + position_code.len() + public_key.len());
    append_lp(&mut m, PUBLIC_KEY_LABEL);
    append_lp(&mut m, suite_id.as_bytes());
    append_lp(&mut m, position_code.as_bytes());
    m.extend_from_slice(&key_version.to_be_bytes());
    append_lp(&mut m, public_key);
    m
}

/// The bytes signed for a CTS1 ciphertext (the ciphertext enters as its SHA-256).
pub fn ciphertext_message(document_id: &str, version: u32, ciphertext: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(96 + document_id.len());
    append_lp(&mut m, CIPHERTEXT_LABEL);
    append_lp(&mut m, document_id.as_bytes());
    m.extend_from_slice(&version.to_be_bytes());
    append_lp(&mut m, &hash::sha256(ciphertext));
    m
}

/// `magic || lp(signature)`, the part of a signed envelope before its body.
pub fn envelope_prefix(magic: &[u8; 4], signature: &str) -> Vec<u8> {
    let mut p = Vec::with_capacity(8 + signature.len());
    p.extend_from_slice(magic);
    append_lp(&mut p, signature.as_bytes());
    p
}

pub fn seal_envelope(magic: &[u8; 4], signature: &str, body: &[u8]) -> Vec<u8> {
    let mut out = envelope_prefix(magic, signature);
    out.extend_from_slice(body);
    out
}

pub struct Envelope<'a> {
    pub signature: &'a str,
    pub body: &'a [u8],
    pub body_offset: usize,
}

/// Splits a signed envelope; `None` if it is not one of kind `magic`.
pub fn open_envelope<'a>(magic: &[u8; 4], data: &'a [u8]) -> Option<Envelope<'a>> {
    let rest = data.strip_prefix(&magic[..])?;
    let (len, rest) = rest.split_first_chunk::<4>()?;
    let len = u32::from_be_bytes(*len) as usize;
    if len == 0 || len > MAX_SIGNATURE_LEN || rest.len() < len {
        return None;
    }
    let (signature, body) = rest.split_at(len);
    Some(Envelope {
        signature: std::str::from_utf8(signature).ok()?,
        body,
        body_offset: 8 + len,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jkb1_round_trip() {
        let id = KeyIdentity {
            position_code: "HEAD-OF-BUREAU".into(),
            key_version: 3,
            suite_id: "S".into(),
        };
        let b = encode_jkb1(&id, b"private");
        let (got, key) = decode_jkb1(&b).unwrap();
        assert_eq!((got, &key[..]), (id, &b"private"[..]));
        let mut trailing = b.to_vec();
        trailing.push(0);
        assert!(decode_jkb1(&trailing).is_none());
    }

    #[test]
    fn jkb1_malformed() {
        let cases: [&[u8]; 4] = [
            b"",
            b"JKB1",
            b"XXXX\x00\x00\x00\x01a",
            b"JKB1\xff\xff\xff\xff",
        ];
        for bad in cases {
            assert!(decode_jkb1(bad).is_none());
        }
    }

    #[test]
    fn envelope_round_trip() {
        let sealed = seal_envelope(PUBLIC_KEY_MAGIC, "vault:v1:abc", b"body");
        let env = open_envelope(PUBLIC_KEY_MAGIC, &sealed).unwrap();
        assert_eq!((env.signature, env.body), ("vault:v1:abc", &b"body"[..]));
        assert_eq!(&sealed[env.body_offset..], b"body");
    }

    #[test]
    fn malformed_envelopes_rejected() {
        let sealed = seal_envelope(PUBLIC_KEY_MAGIC, "sig", b"body");
        assert!(open_envelope(CIPHERTEXT_MAGIC, &sealed).is_none());
        assert!(open_envelope(PUBLIC_KEY_MAGIC, &sealed[..9]).is_none());
        assert!(open_envelope(PUBLIC_KEY_MAGIC, b"PKS1").is_none());
        assert!(open_envelope(PUBLIC_KEY_MAGIC, b"PKS1\x00\x00\x00\x00body").is_none());
        assert!(open_envelope(PUBLIC_KEY_MAGIC, b"PKS1\xff\xff\xff\xffbody").is_none());
        assert!(open_envelope(PUBLIC_KEY_MAGIC, b"PKS1\x00\x00\x00\x02\xff\xfebody").is_none());
        assert!(open_envelope(PUBLIC_KEY_MAGIC, b"").is_none());
    }

    #[test]
    fn messages_bind_every_field() {
        let base = public_key_message("S", "P", 1, b"K");
        for other in [
            public_key_message("S2", "P", 1, b"K"),
            public_key_message("S", "P2", 1, b"K"),
            public_key_message("S", "P", 2, b"K"),
            public_key_message("S", "P", 1, b"K2"),
        ] {
            assert_ne!(base, other);
        }
        let base = ciphertext_message("D", 1, b"C");
        for other in [
            ciphertext_message("D2", 1, b"C"),
            ciphertext_message("D", 2, b"C"),
            ciphertext_message("D", 1, b"C2"),
        ] {
            assert_ne!(base, other);
        }
    }
}
