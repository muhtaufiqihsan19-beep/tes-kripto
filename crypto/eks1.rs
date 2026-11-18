//! EKS1: the document ciphertext format and its chunked AES-256-GCM encryption.
//!
//! `header || chunk_0 || ... || chunk_n`, each chunk `AES-256-GCM(DEK, piece) || tag`.
//! - Header: `"EKS1" || 0x01 || lp16(content_alg) || lp16(document_id) || version ||
//!   chunk_size || 8-byte random nonce prefix`.
//! - Nonce of chunk `i`: `prefix || i` (big-endian u32), so no nonce repeats under one DEK.
//! - AAD of chunk `i`: `SHA-256(header) || i || last-chunk flag`, so chunks cannot be
//!   reordered, dropped, moved to another document or cut off at the end.

use std::io::{self, BufRead, BufReader, Read, Write};

use thiserror::Error;
use zeroize::Zeroizing;

use crate::crypto::primitives::aes::{self, Aes256Gcm};
use crate::crypto::primitives::{hash, random};

pub const CONTENT_ALG: &str = "AES256GCM-CHUNK-v1";
pub const DEFAULT_CHUNK_SIZE: u32 = 1 << 20;

const MAGIC: &[u8; 4] = b"EKS1";
const FORMAT_VERSION: u8 = 1;
const TAG_LEN: usize = aes::TAG_LEN;
const PREFIX_LEN: usize = 8;
const MIN_CHUNK: u32 = 4 << 10;
const MAX_CHUNK: u32 = 16 << 20;
const MAX_FIELD: usize = 1024;

#[derive(Debug, Error)]
pub enum Eks1Error {
    #[error("invalid EKS1 format")]
    Format,
    #[error("EKS1 authentication failed")]
    Auth,
    #[error("DEK must be 32 bytes")]
    BadKey,
    #[error("internal EKS1 crypto failure")]
    Internal,
    #[error("I/O: {0}")]
    Io(#[from] io::Error),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    pub document_id: String,
    pub version: u32,
    pub chunk_size: u32,
    pub content_alg: String,
    prefix: [u8; PREFIX_LEN],
}

impl Header {
    fn new(document_id: &str, version: u32, chunk_size: u32, prefix: [u8; PREFIX_LEN]) -> Self {
        Header {
            document_id: document_id.to_string(),
            version,
            chunk_size: if chunk_size == 0 {
                DEFAULT_CHUNK_SIZE
            } else {
                chunk_size
            },
            content_alg: CONTENT_ALG.to_string(),
            prefix,
        }
    }

    fn marshal(&self) -> Result<Vec<u8>, Eks1Error> {
        if self.document_id.is_empty()
            || self.document_id.len() > MAX_FIELD
            || self.version == 0
            || !(MIN_CHUNK..=MAX_CHUNK).contains(&self.chunk_size)
        {
            return Err(Eks1Error::Format);
        }
        let mut b = Vec::with_capacity(64 + self.document_id.len());
        b.extend_from_slice(MAGIC);
        b.push(FORMAT_VERSION);
        push_lp16(&mut b, self.content_alg.as_bytes());
        push_lp16(&mut b, self.document_id.as_bytes());
        b.extend_from_slice(&self.version.to_be_bytes());
        b.extend_from_slice(&self.chunk_size.to_be_bytes());
        b.extend_from_slice(&self.prefix);
        Ok(b)
    }

    pub fn plaintext_len(&self, body_len: usize) -> usize {
        let sealed = self.chunk_size as usize + TAG_LEN;
        let chunks = body_len.div_ceil(sealed).max(1);
        body_len.saturating_sub(chunks * TAG_LEN)
    }
}

fn push_lp16(b: &mut Vec<u8>, v: &[u8]) {
    b.extend_from_slice(&(v.len() as u16).to_be_bytes());
    b.extend_from_slice(v);
}

pub fn read_header<R: Read>(r: &mut R) -> Result<(Header, Vec<u8>), Eks1Error> {
    let mut raw = Vec::with_capacity(128);
    let mut fixed = [0u8; 5];
    r.read_exact(&mut fixed).map_err(|_| Eks1Error::Format)?;
    if &fixed[..4] != MAGIC || fixed[4] != FORMAT_VERSION {
        return Err(Eks1Error::Format);
    }
    raw.extend_from_slice(&fixed);

    let read_lp = |r: &mut R, raw: &mut Vec<u8>| -> Result<String, Eks1Error> {
        let mut l = [0u8; 2];
        r.read_exact(&mut l).map_err(|_| Eks1Error::Format)?;
        let n = u16::from_be_bytes(l) as usize;
        if n == 0 || n > MAX_FIELD {
            return Err(Eks1Error::Format);
        }
        let mut v = vec![0u8; n];
        r.read_exact(&mut v).map_err(|_| Eks1Error::Format)?;
        raw.extend_from_slice(&l);
        raw.extend_from_slice(&v);
        String::from_utf8(v).map_err(|_| Eks1Error::Format)
    };
    let content_alg = read_lp(r, &mut raw)?;
    if content_alg != CONTENT_ALG {
        return Err(Eks1Error::Format);
    }
    let document_id = read_lp(r, &mut raw)?;

    let mut tail = [0u8; 8 + PREFIX_LEN];
    r.read_exact(&mut tail).map_err(|_| Eks1Error::Format)?;
    raw.extend_from_slice(&tail);
    let version = u32::from_be_bytes(tail[0..4].try_into().unwrap());
    let chunk_size = u32::from_be_bytes(tail[4..8].try_into().unwrap());
    let mut prefix = [0u8; PREFIX_LEN];
    prefix.copy_from_slice(&tail[8..]);
    if version == 0 || !(MIN_CHUNK..=MAX_CHUNK).contains(&chunk_size) {
        return Err(Eks1Error::Format);
    }
    Ok((
        Header {
            document_id,
            version,
            chunk_size,
            content_alg,
            prefix,
        },
        raw,
    ))
}

const AAD_LEN: usize = 32 + 4 + 1;

fn chunk_aad(header_hash: &[u8], index: u32, last: bool) -> [u8; AAD_LEN] {
    let mut aad = [0u8; AAD_LEN];
    aad[..32].copy_from_slice(header_hash);
    aad[32..36].copy_from_slice(&index.to_be_bytes());
    aad[36] = u8::from(last);
    aad
}

fn chunk_nonce(prefix: &[u8; PREFIX_LEN], index: u32) -> [u8; aes::NONCE_LEN] {
    let mut n = [0u8; aes::NONCE_LEN];
    n[..PREFIX_LEN].copy_from_slice(prefix);
    n[PREFIX_LEN..].copy_from_slice(&index.to_be_bytes());
    n
}

fn aead_key(dek: &[u8]) -> Result<Aes256Gcm, Eks1Error> {
    if dek.len() != aes::KEY_LEN {
        return Err(Eks1Error::BadKey);
    }
    Aes256Gcm::new(dek).map_err(|_| Eks1Error::BadKey)
}

fn random_prefix() -> Result<[u8; PREFIX_LEN], Eks1Error> {
    random::bytes::<PREFIX_LEN>().map_err(|_| Eks1Error::Internal)
}

fn read_full<R: Read>(r: &mut R, buf: &mut [u8]) -> io::Result<usize> {
    let mut n = 0;
    while n < buf.len() {
        match r.read(&mut buf[n..]) {
            Ok(0) => break,
            Ok(k) => n += k,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(n)
}

fn at_eof<R: BufRead>(r: &mut R) -> io::Result<bool> {
    Ok(r.fill_buf()?.is_empty())
}

pub fn encrypt<R: Read, W: Write>(
    dst: &mut W,
    src: R,
    dek: &[u8],
    document_id: &str,
    version: u32,
    chunk_size: u32,
) -> Result<(), Eks1Error> {
    let h = Header::new(document_id, version, chunk_size, random_prefix()?);
    encrypt_with_header(dst, src, dek, &h)
}

fn encrypt_with_header<R: Read, W: Write>(
    dst: &mut W,
    src: R,
    dek: &[u8],
    h: &Header,
) -> Result<(), Eks1Error> {
    let key = aead_key(dek)?;
    let hdr = h.marshal()?;
    dst.write_all(&hdr)?;
    let hh = hash::sha256(&hdr);

    let cs = h.chunk_size as usize;
    let mut src = BufReader::with_capacity(cs + 1, src);
    let mut buf = Zeroizing::new(vec![0u8; cs]);
    let mut index: u32 = 0;
    loop {
        let n = read_full(&mut src, &mut buf)?;
        let last = n < cs || at_eof(&mut src)?;
        let tag = key
            .seal_separate_tag(
                chunk_nonce(&h.prefix, index),
                &chunk_aad(&hh, index, last),
                &mut buf[..n],
            )
            .map_err(|_| Eks1Error::Internal)?;
        dst.write_all(&buf[..n])?;
        dst.write_all(&tag)?;
        if last {
            return Ok(());
        }
        index = index.checked_add(1).ok_or(Eks1Error::Format)?;
    }
}

pub fn encrypt_to_vec(
    plaintext: &[u8],
    dek: &[u8],
    document_id: &str,
    version: u32,
    chunk_size: u32,
) -> Result<Vec<u8>, Eks1Error> {
    let h = Header::new(document_id, version, chunk_size, random_prefix()?);
    encrypt_to_vec_with_header(plaintext, dek, &h)
}

fn encrypt_to_vec_with_header(
    plaintext: &[u8],
    dek: &[u8],
    h: &Header,
) -> Result<Vec<u8>, Eks1Error> {
    let key = aead_key(dek)?;
    let hdr = h.marshal()?;
    let hh = hash::sha256(&hdr);

    let cs = h.chunk_size as usize;
    let chunks = plaintext.len().div_ceil(cs).max(1);
    let last_index = u32::try_from(chunks - 1).map_err(|_| Eks1Error::Format)?;
    let mut out = Vec::with_capacity(hdr.len() + plaintext.len() + chunks * TAG_LEN);
    out.extend_from_slice(&hdr);
    for index in 0..=last_index {
        let from = index as usize * cs;
        let piece = &plaintext[from..(from + cs).min(plaintext.len())];
        let at = out.len();
        out.extend_from_slice(piece);
        let last = index == last_index;
        let tag = key
            .seal_separate_tag(
                chunk_nonce(&h.prefix, index),
                &chunk_aad(&hh, index, last),
                &mut out[at..],
            )
            .map_err(|_| Eks1Error::Internal)?;
        out.extend_from_slice(&tag);
    }
    debug_assert_eq!(out.len(), out.capacity());
    Ok(out)
}

/// Streaming decryption: writes each chunk to `dst` as soon as that chunk is authenticated.
/// Truncation is only detected at the end, so on `Err` the caller must discard everything
/// already written. The service uses [`decrypt_in_place`], which hands out plaintext only
/// after every chunk and the final-chunk marker have been verified.
pub fn decrypt<R: Read, W: Write>(dst: &mut W, src: R, dek: &[u8]) -> Result<Header, Eks1Error> {
    let key = aead_key(dek)?;
    let mut src = src;
    let (h, raw) = read_header(&mut src)?;
    let hh = hash::sha256(&raw);

    let sealed_len = h.chunk_size as usize + TAG_LEN;
    let mut src = BufReader::with_capacity(sealed_len + 1, src);
    let mut buf = Zeroizing::new(vec![0u8; sealed_len]);
    let mut index: u32 = 0;
    loop {
        let n = read_full(&mut src, &mut buf)?;
        if n < TAG_LEN {
            return Err(Eks1Error::Auth);
        }
        let last = n < sealed_len || at_eof(&mut src)?;
        let plain = key
            .open(
                chunk_nonce(&h.prefix, index),
                &chunk_aad(&hh, index, last),
                &mut buf[..n],
            )
            .map_err(|_| Eks1Error::Auth)?;
        dst.write_all(plain)?;
        if last {
            return Ok(h);
        }
        index = index.checked_add(1).ok_or(Eks1Error::Format)?;
    }
}

/// Decrypts a whole EKS1 file in place. Returns `Ok` only after every chunk and the
/// final-chunk marker are authenticated; on `Err` the buffer holds partial output and must
/// be discarded (the service drops it as a `Zeroizing` buffer).
pub fn decrypt_in_place(buf: &mut Vec<u8>, dek: &[u8]) -> Result<Header, Eks1Error> {
    let key = aead_key(dek)?;
    let (h, raw) = read_header(&mut &buf[..])?;
    let hh = hash::sha256(&raw);

    let sealed_len = h.chunk_size as usize + TAG_LEN;
    let (mut read, mut write) = (raw.len(), 0usize);
    let mut index: u32 = 0;
    loop {
        let remaining = buf.len() - read;
        let n = remaining.min(sealed_len);
        if n < TAG_LEN {
            return Err(Eks1Error::Auth);
        }
        let last = remaining <= sealed_len;
        let plain_len = key
            .open(
                chunk_nonce(&h.prefix, index),
                &chunk_aad(&hh, index, last),
                &mut buf[read..read + n],
            )
            .map_err(|_| Eks1Error::Auth)?
            .len();
        buf.copy_within(read..read + plain_len, write);
        write += plain_len;
        read += n;
        if last {
            buf.truncate(write);
            return Ok(h);
        }
        index = index.checked_add(1).ok_or(Eks1Error::Format)?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CS: u32 = 4096;

    fn dek() -> Vec<u8> {
        let mut k = vec![0u8; 32];
        random::fill(&mut k).unwrap();
        k
    }

    fn seal(key: &[u8], plain: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        encrypt(&mut out, plain, key, "ND-2026-0001", 3, CS).unwrap();
        out
    }

    fn open(key: &[u8], ct: &[u8]) -> Result<(Vec<u8>, Header), Eks1Error> {
        let mut out = Vec::new();
        let h = decrypt(&mut out, ct, key)?;
        Ok((out, h))
    }

    fn header_len(ct: &[u8]) -> usize {
        let mut r = ct;
        read_header(&mut r).unwrap().1.len()
    }

    fn random(n: usize) -> Vec<u8> {
        let mut v = vec![0u8; n];
        random::fill(&mut v).unwrap();
        v
    }

    #[test]
    fn round_trip_sizes() {
        let key = dek();
        for n in [0usize, 1, 4095, 4096, 4097, 8192, 3 * 4096 + 17] {
            let plain = random(n);
            let (got, h) = open(&key, &seal(&key, &plain)).unwrap();
            assert_eq!(got, plain, "n={n}");
            assert_eq!(
                (h.document_id.as_str(), h.version, h.chunk_size),
                ("ND-2026-0001", 3, CS)
            );
        }
    }

    #[test]
    fn nonce_prefix_random() {
        let key = dek();
        assert_ne!(seal(&key, b"x"), seal(&key, b"x"));
    }

    #[test]
    fn tamper_detection() {
        let key = dek();
        let ct = seal(&key, &random(3 * 4096 + 10));
        let hl = header_len(&ct);
        let sc = CS as usize + TAG_LEN;
        let chunk = |i: usize| ct[hl + i * sc..(hl + (i + 1) * sc).min(ct.len())].to_vec();
        let cat = |parts: &[Vec<u8>]| parts.concat();
        let flip = |i: usize| {
            let mut c = ct.clone();
            c[i] ^= 1;
            c
        };
        let head = ct[..hl].to_vec();
        let cases: Vec<(&str, Vec<u8>)> = vec![
            ("truncated at chunk boundary", ct[..hl + 2 * sc].to_vec()),
            ("truncated mid-chunk", ct[..hl + sc + 100].to_vec()),
            ("header only", head.clone()),
            (
                "chunks swapped",
                cat(&[head.clone(), chunk(1), chunk(0), chunk(2), chunk(3)]),
            ),
            (
                "chunk removed",
                cat(&[head.clone(), chunk(0), chunk(2), chunk(3)]),
            ),
            (
                "chunk duplicated",
                cat(&[
                    head.clone(),
                    chunk(0),
                    chunk(0),
                    chunk(1),
                    chunk(2),
                    chunk(3),
                ]),
            ),
            ("trailing garbage", cat(&[ct.clone(), vec![0]])),
            ("body bit flipped", flip(hl + 2000)),
            ("tag bit flipped", flip(ct.len() - 1)),
            ("nonce prefix flipped", flip(hl - 1)),
            ("header version flipped", flip(hl - PREFIX_LEN - 5)),
        ];
        for (name, bad) in cases {
            assert!(open(&key, &bad).is_err(), "{name}: must fail");
        }
        assert!(matches!(open(&dek(), &ct), Err(Eks1Error::Auth)));
    }

    #[test]
    fn header_swap_between_documents() {
        let key = dek();
        let (mut a, mut b) = (Vec::new(), Vec::new());
        encrypt(&mut a, &b"content A"[..], &key, "DOC-A", 1, CS).unwrap();
        encrypt(&mut b, &b"content B"[..], &key, "DOC-B", 1, CS).unwrap();
        let mixed = [&a[..header_len(&a)], &b[header_len(&b)..]].concat();
        assert!(open(&key, &mixed).is_err());
    }

    #[test]
    fn in_memory_matches_streaming() {
        let key = dek();
        for n in [0usize, 1, 4095, 4096, 4097, 8192, 3 * 4096 + 17] {
            let plain = random(n);
            let h = Header::new("ND-2026-0001", 3, CS, [7u8; PREFIX_LEN]);
            let mut streamed = Vec::new();
            encrypt_with_header(&mut streamed, &plain[..], &key, &h).unwrap();
            let in_memory = encrypt_to_vec_with_header(&plain, &key, &h).unwrap();
            assert_eq!(streamed, in_memory, "n={n}: output must be identical");

            let mut buf = in_memory.clone();
            let got = decrypt_in_place(&mut buf, &key).unwrap();
            assert_eq!(buf, plain, "n={n}");
            assert_eq!(got, h);
            assert_eq!(h.plaintext_len(in_memory.len() - header_len(&in_memory)), n);
        }
    }

    #[test]
    fn in_place_tamper_detection() {
        let key = dek();
        let ct = seal(&key, &random(3 * 4096 + 10));
        let hl = header_len(&ct);
        let sc = CS as usize + TAG_LEN;
        for bad in [
            ct[..hl + 2 * sc].to_vec(),
            ct[..hl + sc + 100].to_vec(),
            ct[..hl].to_vec(),
            [ct.clone(), vec![0]].concat(),
            {
                let mut c = ct.clone();
                c[hl + 2000] ^= 1;
                c
            },
            {
                let mut c = ct.clone();
                c[hl - 1] ^= 1;
                c
            },
        ] {
            let mut b = bad.clone();
            let mut out = Vec::new();
            assert_eq!(
                decrypt_in_place(&mut b, &key).is_err(),
                decrypt(&mut out, &bad[..], &key).is_err()
            );
            assert!(decrypt_in_place(&mut bad.clone(), &key).is_err());
        }
        assert!(matches!(
            decrypt_in_place(&mut ct.clone(), &dek()),
            Err(Eks1Error::Auth)
        ));
    }

    #[test]
    fn rejects_bad_params() {
        let mut out = Vec::new();
        assert!(encrypt(&mut out, &b""[..], &[0u8; 16], "D", 1, CS).is_err());
        assert!(encrypt(&mut out, &b""[..], &dek(), "", 1, CS).is_err());
        assert!(encrypt(&mut out, &b""[..], &dek(), "D", 1, 100).is_err());
        assert!(matches!(
            encrypt_to_vec(b"", &dek(), "", 1, CS),
            Err(Eks1Error::Format)
        ));
    }
}
