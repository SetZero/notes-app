//! Key derivation and block encryption (design/protocol/06-keys-and-envelope).
//!
//! Byte-exact definitions, so that every platform and every later version
//! derives the same keys:
//!
//! * note key          = HKDF-SHA256(ikm = AK, no salt, info = "notes/v1/note" | note_id[16])
//! * recovery verifier = HKDF-SHA256(ikm = AK, no salt, info = "notes/v1/recovery")
//! * AAD               = "notes/v1" | block_id[16] | note_id[16] | version[24 ASCII] | deleted[1]
//! * ciphertext        = AES-256-GCM(note key, nonce[12 random], payload, AAD), tag appended

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use alloc::string::String;
use alloc::vec::Vec;
use hkdf::Hkdf;
use sha2::Sha256;
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
        .encrypt(Nonce::from_slice(nonce), Payload { msg: plaintext, aad })
        .expect("AES-GCM encryption only fails for absurdly long inputs")
}

/// `None` when the ciphertext, the nonce or anything bound into the AAD was
/// changed, or the key is wrong.
pub fn open(key: &[u8; KEY_LEN], nonce: &[u8], ciphertext: &[u8], aad: &[u8]) -> Option<Vec<u8>> {
    if nonce.len() != NONCE_LEN || ciphertext.len() < TAG_LEN {
        return None;
    }
    Aes256Gcm::new(key.into())
        .decrypt(Nonce::from_slice(nonce), Payload { msg: ciphertext, aad })
        .ok()
}

/// The account key as 24 words (BIP-39, English).
pub fn recovery_phrase(ak: &AccountKey) -> String {
    let mnemonic = bip39::Mnemonic::from_entropy(&ak.0).expect("32 bytes is a valid BIP-39 entropy length");
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
    let mnemonic = bip39::Mnemonic::parse_in_normalized(bip39::Language::English, &normalized).ok()?;
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
        assert!(open(&key, &[9; 12], &sealed, &aad(&[8; 16], &[1; 16], version, false)).is_none());
        assert!(open(&key, &[9; 12], &sealed, &aad(&[7; 16], &[2; 16], version, false)).is_none());
        assert!(open(&key, &[9; 12], &sealed, &aad(&[7; 16], &[1; 16], "0123456789ab0001deadbeef", false)).is_none());
        assert!(open(&key, &[9; 12], &sealed, &aad(&[7; 16], &[1; 16], version, true)).is_none());
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
}
