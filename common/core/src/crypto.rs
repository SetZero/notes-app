//! Key derivation and block encryption (design/protocol/06-keys-and-envelope).
//!
//! Byte-exact definitions, so that every platform and every later version
//! derives the same keys:
//!
//! * note key          = HKDF-SHA256(ikm = AK, no salt, info = "notes/v1/note" | note_id[16])
//! * recovery verifier = HKDF-SHA256(ikm = AK, no salt, info = "notes/v1/recovery")
//! * AAD               = "notes/v1" | block_id[16] | note_id[16] | version[24 ASCII] | deleted[1]
//! * ciphertext        = AES-256-GCM(note key, nonce[12 random], payload, AAD), tag appended
//!
//! Attachments (design/protocol/04-attachment-transfer):
//!
//! * blob key   = 32 random bytes, one per attachment, kept in the attachment block
//! * blob       = prefix[7 random] | chunk 0 | chunk 1 | ...
//! * chunk i    = AES-256-GCM(blob key, nonce = prefix | i[4, big endian] | last[1],
//!   plaintext[i * 64 KiB ..][.. 64 KiB], no AAD), tag appended
//! * `last` is 1 for the final chunk and 0 otherwise, so a blob cannot be cut
//!   short; an empty file is one empty chunk
//! * blob hash  = SHA-256(blob), lower-case hex: its name on the server

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use alloc::string::String;
use alloc::vec::Vec;
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

pub const KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 12;
pub const TAG_LEN: usize = 16;

/// The account key. Wiped from memory when dropped.
#[derive(Clone)]
pub struct AccountKey(pub [u8; KEY_LEN]);

impl Drop for AccountKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// The key that wraps the account key on its way to a device being paired:
/// HKDF-SHA256 of the SPAKE2 result, bound to the pairing it belongs to.
pub fn pairing_key(shared: &[u8], pairing_id: &str) -> [u8; KEY_LEN] {
    let mut out = [0u8; KEY_LEN];
    Hkdf::<Sha256>::new(None, shared)
        .expand_multi_info(&[b"notes/pairing/v1/", pairing_id.as_bytes()], &mut out)
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    out
}

fn expand(ak: &AccountKey, info: &[&[u8]]) -> [u8; KEY_LEN] {
    let mut out = [0u8; KEY_LEN];
    Hkdf::<Sha256>::new(None, &ak.0)
        .expand_multi_info(info, &mut out)
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    out
}

pub fn note_key(ak: &AccountKey, note_id: &[u8; 16]) -> [u8; KEY_LEN] {
    expand(ak, &[b"notes/v1/note", note_id])
}

pub fn recovery_verifier(ak: &AccountKey) -> [u8; KEY_LEN] {
    expand(ak, &[b"notes/v1/recovery"])
}

pub fn aad(block_id: &[u8; 16], note_id: &[u8; 16], version: &str, deleted: bool) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + 16 + 16 + version.len() + 1);
    out.extend_from_slice(b"notes/v1");
    out.extend_from_slice(block_id);
    out.extend_from_slice(note_id);
    out.extend_from_slice(version.as_bytes());
    out.push(u8::from(deleted));
    out
}

pub fn seal(key: &[u8; KEY_LEN], nonce: &[u8; NONCE_LEN], plaintext: &[u8], aad: &[u8]) -> Vec<u8> {
    Aes256Gcm::new(key.into())
        .encrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .expect("AES-GCM encryption only fails for absurdly long inputs")
}

/// `None` when the ciphertext, the nonce or anything bound into the AAD was
/// changed, or the key is wrong.
pub fn open(key: &[u8; KEY_LEN], nonce: &[u8], ciphertext: &[u8], aad: &[u8]) -> Option<Vec<u8>> {
    if nonce.len() != NONCE_LEN || ciphertext.len() < TAG_LEN {
        return None;
    }
    Aes256Gcm::new(key.into())
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .ok()
}

pub const BLOB_CHUNK_LEN: usize = 64 * 1024;
pub const BLOB_PREFIX_LEN: usize = 7;

fn blob_nonce(prefix: &[u8], index: u32, last: bool) -> [u8; NONCE_LEN] {
    let mut nonce = [0u8; NONCE_LEN];
    nonce[..BLOB_PREFIX_LEN].copy_from_slice(prefix);
    nonce[BLOB_PREFIX_LEN..BLOB_PREFIX_LEN + 4].copy_from_slice(&index.to_be_bytes());
    nonce[NONCE_LEN - 1] = u8::from(last);
    nonce
}

/// Encrypts an attachment. `key` must be used for this one blob only.
pub fn seal_blob(key: &[u8; KEY_LEN], prefix: &[u8; BLOB_PREFIX_LEN], plaintext: &[u8]) -> Vec<u8> {
    let cipher = Aes256Gcm::new(key.into());
    let chunks = plaintext.len().div_ceil(BLOB_CHUNK_LEN).max(1);
    let mut out = Vec::with_capacity(BLOB_PREFIX_LEN + plaintext.len() + chunks * TAG_LEN);
    out.extend_from_slice(prefix);
    for index in 0..chunks {
        let start = index * BLOB_CHUNK_LEN;
        let end = plaintext.len().min(start + BLOB_CHUNK_LEN);
        let nonce = blob_nonce(prefix, index as u32, index + 1 == chunks);
        let sealed = cipher
            .encrypt(Nonce::from_slice(&nonce), &plaintext[start..end])
            .expect("AES-GCM encryption only fails for absurdly long inputs");
        out.extend_from_slice(&sealed);
    }
    out
}

/// `None` when any part of the blob was changed, removed, reordered or cut
/// off, or the key is wrong.
pub fn open_blob(key: &[u8; KEY_LEN], blob: &[u8]) -> Option<Vec<u8>> {
    const SEALED_CHUNK_LEN: usize = BLOB_CHUNK_LEN + TAG_LEN;
    if blob.len() < BLOB_PREFIX_LEN + TAG_LEN {
        return None;
    }
    let (prefix, mut rest) = blob.split_at(BLOB_PREFIX_LEN);
    let cipher = Aes256Gcm::new(key.into());
    let mut out = Vec::with_capacity(rest.len());
    let mut index: u32 = 0;
    loop {
        let last = rest.len() <= SEALED_CHUNK_LEN;
        let (chunk, tail) = rest.split_at(rest.len().min(SEALED_CHUNK_LEN));
        let nonce = blob_nonce(prefix, index, last);
        let Ok(mut plain) = cipher.decrypt(Nonce::from_slice(&nonce), chunk) else {
            out.zeroize();
            return None;
        };
        out.extend_from_slice(&plain);
        plain.zeroize();
        if last {
            return Some(out);
        }
        rest = tail;
        index = index.checked_add(1)?;
    }
}

pub fn sha256_hex(data: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(64);
    for byte in Sha256::digest(data) {
        out.push(HEX[usize::from(byte >> 4)] as char);
        out.push(HEX[usize::from(byte & 15)] as char);
    }
    out
}

/// The account key as 24 words (BIP-39, English).
pub fn recovery_phrase(ak: &AccountKey) -> String {
    let mnemonic =
        bip39::Mnemonic::from_entropy(&ak.0).expect("32 bytes is a valid BIP-39 entropy length");
    let mut phrase = String::new();
    for word in mnemonic.words() {
        if !phrase.is_empty() {
            phrase.push(' ');
        }
        phrase.push_str(word);
    }
    phrase
}

/// Accepts any spacing and letter case. `None` for a wrong word, a wrong
/// number of words or a wrong checksum.
pub fn account_key_from_phrase(phrase: &str) -> Option<AccountKey> {
    let mut normalized = String::new();
    for word in phrase.split_whitespace() {
        if !normalized.is_empty() {
            normalized.push(' ');
        }
        for ch in word.chars() {
            normalized.extend(ch.to_lowercase());
        }
    }
    let mnemonic =
        bip39::Mnemonic::parse_in_normalized(bip39::Language::English, &normalized).ok()?;
    normalized.zeroize();
    let (mut entropy, len) = mnemonic.to_entropy_array();
    if len != KEY_LEN {
        entropy.zeroize();
        return None;
    }
    let mut key = [0u8; KEY_LEN];
    key.copy_from_slice(&entropy[..KEY_LEN]);
    entropy.zeroize();
    Some(AccountKey(key))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ak() -> AccountKey {
        AccountKey(core::array::from_fn(|i| i as u8))
    }

    #[test]
    fn phrase_round_trips_and_rejects_typos() {
        let phrase = recovery_phrase(&ak());
        assert_eq!(phrase.split(' ').count(), 24);
        let shouted = phrase.to_uppercase().replace(' ', "  \n ");
        assert_eq!(account_key_from_phrase(&shouted).unwrap().0, ak().0);
        // Swapping two different words breaks the checksum.
        let mut words: Vec<&str> = phrase.split(' ').collect();
        let other = (1..24).find(|i| words[*i] != words[0]).unwrap();
        words.swap(0, other);
        assert!(account_key_from_phrase(&words.join(" ")).is_none());
        assert!(account_key_from_phrase("abandon ability able").is_none());
        assert!(account_key_from_phrase("").is_none());
    }

    #[test]
    fn keys_are_separated_by_purpose_and_note() {
        let a = note_key(&ak(), &[1; 16]);
        let b = note_key(&ak(), &[2; 16]);
        assert_ne!(a, b);
        assert_ne!(a, recovery_verifier(&ak()));
        assert_ne!(recovery_verifier(&ak()), ak().0);
    }

    #[test]
    fn anything_bound_into_the_tag_cannot_be_changed() {
        let key = note_key(&ak(), &[1; 16]);
        let version = "0123456789ab0000deadbeef";
        let good = aad(&[7; 16], &[1; 16], version, false);
        let sealed = seal(&key, &[9; 12], b"hello", &good);
        assert_eq!(open(&key, &[9; 12], &sealed, &good).unwrap(), b"hello");

        // Moved to another block, another note, another version, or turned
        // into a deletion marker: all refused.
        assert!(open(
            &key,
            &[9; 12],
            &sealed,
            &aad(&[8; 16], &[1; 16], version, false)
        )
        .is_none());
        assert!(open(
            &key,
            &[9; 12],
            &sealed,
            &aad(&[7; 16], &[2; 16], version, false)
        )
        .is_none());
        assert!(open(
            &key,
            &[9; 12],
            &sealed,
            &aad(&[7; 16], &[1; 16], "0123456789ab0001deadbeef", false)
        )
        .is_none());
        assert!(open(
            &key,
            &[9; 12],
            &sealed,
            &aad(&[7; 16], &[1; 16], version, true)
        )
        .is_none());
        // Wrong key, changed ciphertext, wrong nonce.
        assert!(open(&note_key(&ak(), &[2; 16]), &[9; 12], &sealed, &good).is_none());
        let mut flipped = sealed.clone();
        flipped[0] ^= 1;
        assert!(open(&key, &[9; 12], &flipped, &good).is_none());
        assert!(open(&key, &[8; 12], &sealed, &good).is_none());
        assert!(open(&key, &[9; 11], &sealed, &good).is_none());
    }

    #[test]
    fn an_empty_payload_is_just_the_tag() {
        let key = note_key(&ak(), &[1; 16]);
        let aad = aad(&[7; 16], &[1; 16], "0123456789ab0000deadbeef", true);
        let sealed = seal(&key, &[9; 12], b"", &aad);
        assert_eq!(sealed.len(), TAG_LEN);
        assert_eq!(open(&key, &[9; 12], &sealed, &aad).unwrap(), b"");
    }

    #[test]
    fn blobs_round_trip_at_every_chunk_boundary() {
        let key = [3u8; KEY_LEN];
        for len in [
            0,
            1,
            BLOB_CHUNK_LEN - 1,
            BLOB_CHUNK_LEN,
            BLOB_CHUNK_LEN + 1,
            3 * BLOB_CHUNK_LEN,
        ] {
            let plain: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
            let blob = seal_blob(&key, &[5; BLOB_PREFIX_LEN], &plain);
            let chunks = len.div_ceil(BLOB_CHUNK_LEN).max(1);
            assert_eq!(
                blob.len(),
                BLOB_PREFIX_LEN + len + chunks * TAG_LEN,
                "{len}"
            );
            assert_eq!(open_blob(&key, &blob).unwrap(), plain, "{len}");
        }
    }

    #[test]
    fn a_changed_shortened_or_reordered_blob_is_refused() {
        let key = [3u8; KEY_LEN];
        let plain: Vec<u8> = (0..3 * BLOB_CHUNK_LEN + 10)
            .map(|i| (i % 251) as u8)
            .collect();
        let blob = seal_blob(&key, &[5; BLOB_PREFIX_LEN], &plain);
        let sealed_chunk = BLOB_CHUNK_LEN + TAG_LEN;

        assert!(open_blob(&[4u8; KEY_LEN], &blob).is_none());
        let mut flipped = blob.clone();
        flipped[BLOB_PREFIX_LEN + 100] ^= 1;
        assert!(open_blob(&key, &flipped).is_none());
        // Cut after a whole chunk: the last chunk is missing.
        assert!(open_blob(&key, &blob[..BLOB_PREFIX_LEN + sealed_chunk]).is_none());
        assert!(open_blob(&key, &blob[..BLOB_PREFIX_LEN + 3 * sealed_chunk]).is_none());
        assert!(open_blob(&key, &blob[..blob.len() - 1]).is_none());
        assert!(open_blob(&key, &blob[..BLOB_PREFIX_LEN]).is_none());
        // Two chunks swapped.
        let mut swapped = blob.clone();
        let (a, b) = (BLOB_PREFIX_LEN, BLOB_PREFIX_LEN + sealed_chunk);
        swapped[a..a + sealed_chunk].copy_from_slice(&blob[b..b + sealed_chunk]);
        swapped[b..b + sealed_chunk].copy_from_slice(&blob[a..a + sealed_chunk]);
        assert!(open_blob(&key, &swapped).is_none());
    }

    #[test]
    fn sha256_matches_the_standard_test_vector() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
