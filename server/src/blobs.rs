//! Encrypted attachments on the file system, addressed by the SHA-256 of their bytes.
//!
//! Paths are built only from a server-generated account id and a hash that was
//! validated as 64 lower-case hex characters, so no request data can escape the
//! blob directory.

use axum::body::BodyDataStream;
use futures_util::StreamExt;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use tokio::io::AsyncWriteExt;

use crate::util;

pub enum PutOutcome {
    Stored(u64),
    TooLarge,
    HashMismatch,
    /// The client stopped sending or the connection broke.
    Aborted,
}

pub struct BlobStore {
    root: PathBuf,
}

impl BlobStore {
    /// Creates the directories and removes temp files left by an earlier crash.
    pub fn open(data_dir: &Path) -> std::io::Result<Self> {
        let root = data_dir.join("blobs");
        let tmp = root.join("tmp");
        std::fs::create_dir_all(&tmp)?;
        for entry in std::fs::read_dir(&tmp)? {
            let _ = std::fs::remove_file(entry?.path());
        }
        Ok(Self { root })
    }

    fn path(&self, account_id: &str, hash: &str) -> PathBuf {
        debug_assert!(util::is_lower_hex(hash, 64));
        debug_assert!(util::canonical_uuid(account_id).as_deref() == Some(account_id));
        self.root.join(account_id).join(&hash[..2]).join(hash)
    }

    pub async fn open_read(&self, account_id: &str, hash: &str) -> std::io::Result<tokio::fs::File> {
        tokio::fs::File::open(self.path(account_id, hash)).await
    }

    /// Streams the body to a temp file while hashing it, and moves it into place
    /// only if the size is within the limit and the hash matches.
    pub async fn put(
        &self,
        account_id: &str,
        hash: &str,
        mut body: BodyDataStream,
        max_bytes: u64,
    ) -> std::io::Result<PutOutcome> {
        let tmp_path = self.root.join("tmp").join(util::hex(&util::random_bytes::<16>()));
        let mut file = tokio::fs::File::create(&tmp_path).await?;
        let mut hasher = Sha256::new();
        let mut total: u64 = 0;
        let outcome = loop {
            match body.next().await {
                None => break None,
                Some(Err(_)) => break Some(PutOutcome::Aborted),
                Some(Ok(chunk)) => {
                    total += chunk.len() as u64;
                    if total > max_bytes {
                        break Some(PutOutcome::TooLarge);
                    }
                    hasher.update(&chunk);
                    file.write_all(&chunk).await?;
                }
            }
        };
        let outcome = match outcome {
            Some(failed) => failed,
            None if !util::ct_eq(util::hex(&hasher.finalize()).as_bytes(), hash.as_bytes()) => {
                PutOutcome::HashMismatch
            }
            None => {
                file.sync_all().await?;
                drop(file);
                let target = self.path(account_id, hash);
                if let Some(parent) = target.parent() {
                    tokio::fs::create_dir_all(parent).await?;
                }
                tokio::fs::rename(&tmp_path, &target).await?;
                return Ok(PutOutcome::Stored(total));
            }
        };
        let _ = tokio::fs::remove_file(&tmp_path).await;
        Ok(outcome)
    }
}
