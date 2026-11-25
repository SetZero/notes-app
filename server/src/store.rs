//! Database access. One implementation in SQL that SQLite and Postgres share.
//!
//! Rules that keep it portable and safe:
//! - Every value is bound as a parameter; no SQL is built from request data.
//! - Only TEXT, 64-bit integers and blobs are used, and never NULL.
//! - Every write transaction starts with a write statement, so SQLite takes the
//!   write lock immediately and Postgres locks the account row.
//! - Every query on user data is scoped by account id.

use sqlx::any::{AnyPoolOptions, AnyRow};
use sqlx::{AnyPool, Row};

use crate::BoxError;

const SCHEMA_VERSION: i64 = 1;

/// `{INT}` and `{BLOB}` are replaced per database.
const SCHEMA_V1: &str = "
CREATE TABLE accounts (
    id TEXT PRIMARY KEY,
    next_seq {INT} NOT NULL,
    gc_floor {INT} NOT NULL,
    recovery_verifier_hash {BLOB} NOT NULL,
    created_at {INT} NOT NULL
);
CREATE TABLE account_identities (
    provider TEXT NOT NULL,
    subject TEXT NOT NULL,
    account_id TEXT NOT NULL REFERENCES accounts(id),
    PRIMARY KEY (provider, subject)
);
CREATE UNIQUE INDEX account_identities_account ON account_identities (account_id);
CREATE TABLE devices (
    id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES accounts(id),
    name TEXT NOT NULL,
    token_hash {BLOB} NOT NULL UNIQUE,
    last_cursor {INT} NOT NULL,
    last_seen_at {INT} NOT NULL,
    created_at {INT} NOT NULL,
    revoked_at {INT} NOT NULL
);
CREATE INDEX devices_account ON devices (account_id);
CREATE TABLE blocks (
    account_id TEXT NOT NULL REFERENCES accounts(id),
    block_id TEXT NOT NULL,
    note_id TEXT NOT NULL,
    version TEXT NOT NULL,
    deleted {INT} NOT NULL,
    nonce {BLOB} NOT NULL,
    ciphertext {BLOB} NOT NULL,
    seq {INT} NOT NULL,
    origin_device_id TEXT NOT NULL,
    received_at {INT} NOT NULL,
    PRIMARY KEY (account_id, block_id)
);
CREATE UNIQUE INDEX blocks_feed ON blocks (account_id, seq);
CREATE TABLE blobs (
    account_id TEXT NOT NULL REFERENCES accounts(id),
    hash TEXT NOT NULL,
    size {INT} NOT NULL,
    created_at {INT} NOT NULL,
    PRIMARY KEY (account_id, hash)
);
CREATE TABLE pairings (
    id TEXT PRIMARY KEY,
    channel TEXT NOT NULL UNIQUE,
    poll_token_hash {BLOB} NOT NULL,
    device_name TEXT NOT NULL,
    pake_msg_new {BLOB} NOT NULL,
    state TEXT NOT NULL,
    account_id TEXT NOT NULL,
    expires_at {INT} NOT NULL
);
CREATE TABLE pairing_approvals (
    pairing_id TEXT PRIMARY KEY,
    pake_msg_existing {BLOB} NOT NULL,
    wrapped_nonce {BLOB} NOT NULL,
    wrapped_ciphertext {BLOB} NOT NULL
);
CREATE TABLE oidc_nonces (
    nonce_hash {BLOB} PRIMARY KEY,
    provider TEXT NOT NULL,
    expires_at {INT} NOT NULL
)";

#[derive(Debug, Clone)]
pub struct DeviceCtx {
    pub device_id: String,
    pub account_id: String,
}

#[derive(Debug, Clone)]
pub struct DeviceRow {
    pub id: String,
    pub name: String,
    pub created_at: i64,
    pub last_seen_at: i64,
}

#[derive(Debug, Clone)]
pub struct BlockIn {
    pub block_id: String,
    pub note_id: String,
    pub version: String,
    pub deleted: bool,
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct StoredBlock {
    pub block: BlockIn,
    pub seq: i64,
    pub origin_device_id: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Upsert {
    Accepted(i64),
    Duplicate(i64),
    Stale,
}

pub struct ChangeSlice {
    pub blocks: Vec<StoredBlock>,
    pub next_cursor: i64,
    pub has_more: bool,
}

pub struct NewDevice<'a> {
    pub id: &'a str,
    pub name: &'a str,
    pub token_hash: &'a [u8],
}

pub enum CreateAccount {
    Created,
    /// The OIDC identity already owns this account.
    IdentityTaken(String),
}

pub struct AccountAuth {
    pub recovery_verifier_hash: Vec<u8>,
    /// (provider, subject) if the account is bound to an OIDC identity.
    pub identity: Option<(String, String)>,
}

pub struct NewPairing<'a> {
    pub id: &'a str,
    pub channel: &'a str,
    pub poll_token_hash: &'a [u8],
    pub device_name: &'a str,
    pub pake_msg: &'a [u8],
    pub expires_at: i64,
}

pub struct ClaimedPairing {
    pub id: String,
    pub device_name: String,
    pub pake_msg: Vec<u8>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum PairingError {
    NotFound,
    Conflict,
    Expired,
}

pub struct PairingRow {
    pub poll_token_hash: Vec<u8>,
    pub device_name: String,
    pub state: String,
    pub expires_at: i64,
}

pub struct Approval {
    pub account_id: String,
    pub pake_msg: Vec<u8>,
    pub wrapped_nonce: Vec<u8>,
    pub wrapped_ciphertext: Vec<u8>,
}

#[derive(Clone)]
pub struct Store {
    pool: AnyPool,
}

impl Store {
    /// Direct database access, for tests that play a dishonest server.
    #[doc(hidden)]
    pub fn pool(&self) -> &AnyPool {
        &self.pool
    }
}

fn is_unique_violation(e: &sqlx::Error) -> bool {
    matches!(e, sqlx::Error::Database(db) if db.is_unique_violation())
}

fn block_from_row(row: &AnyRow) -> Result<StoredBlock, sqlx::Error> {
    Ok(StoredBlock {
        block: BlockIn {
            block_id: row.try_get(0)?,
            note_id: row.try_get(1)?,
            version: row.try_get(2)?,
            deleted: row.try_get::<i64, _>(3)? != 0,
            nonce: row.try_get(4)?,
            ciphertext: row.try_get(5)?,
        },
        seq: row.try_get(6)?,
        origin_device_id: row.try_get(7)?,
    })
}

impl Store {
    pub async fn connect(database_url: &str) -> Result<Self, BoxError> {
        sqlx::any::install_default_drivers();
        let sqlite = database_url.starts_with("sqlite:");
        let postgres = database_url.starts_with("postgres:") || database_url.starts_with("postgresql:");
        if !sqlite && !postgres {
            return Err("database_url must start with sqlite: or postgres:".into());
        }
        let pool = AnyPoolOptions::new()
            .max_connections(if sqlite { 4 } else { 16 })
            .connect(database_url)
            .await?;
        if sqlite {
            sqlx::query("PRAGMA journal_mode = WAL").execute(&pool).await?;
        }
        let store = Self { pool };
        store.migrate(sqlite).await?;
        Ok(store)
    }

    async fn migrate(&self, sqlite: bool) -> Result<(), BoxError> {
        let (int, blob) = if sqlite { ("INTEGER", "BLOB") } else { ("BIGINT", "BYTEA") };
        let meta = format!("CREATE TABLE IF NOT EXISTS schema_meta (version {int} NOT NULL)");
        sqlx::query(&meta).execute(&self.pool).await?;
        let current: Option<i64> = sqlx::query_scalar("SELECT version FROM schema_meta")
            .fetch_optional(&self.pool)
            .await?;
        match current {
            Some(v) if v == SCHEMA_VERSION => Ok(()),
            Some(v) => Err(format!("database schema version {v} is not supported by this server").into()),
            None => {
                let mut tx = self.pool.begin().await?;
                sqlx::query("INSERT INTO schema_meta (version) VALUES ($1)")
                    .bind(SCHEMA_VERSION)
                    .execute(&mut *tx)
                    .await?;
                let schema = SCHEMA_V1.replace("{INT}", int).replace("{BLOB}", blob);
                for statement in schema.split(';') {
                    sqlx::query(statement.trim()).execute(&mut *tx).await?;
                }
                tx.commit().await?;
                Ok(())
            }
        }
    }

    // ---------------------------------------------------------------- accounts

    pub async fn create_account(
        &self,
        account_id: &str,
        recovery_verifier_hash: &[u8],
        identity: Option<(&str, &str)>,
        device: NewDevice<'_>,
        now: i64,
    ) -> Result<CreateAccount, sqlx::Error> {
        let mut tx = self.pool.begin().await?;
        sqlx::query(
            "INSERT INTO accounts (id, next_seq, gc_floor, recovery_verifier_hash, created_at) \
             VALUES ($1, 1, 0, $2, $3)",
        )
        .bind(account_id)
        .bind(recovery_verifier_hash)
        .bind(now)
        .execute(&mut *tx)
        .await?;
        if let Some((provider, subject)) = identity {
            let inserted = sqlx::query(
                "INSERT INTO account_identities (provider, subject, account_id) VALUES ($1, $2, $3) \
                 ON CONFLICT (provider, subject) DO NOTHING",
            )
            .bind(provider)
            .bind(subject)
            .bind(account_id)
            .execute(&mut *tx)
            .await?
            .rows_affected();
            if inserted == 0 {
                let existing: String = sqlx::query_scalar(
                    "SELECT account_id FROM account_identities WHERE provider = $1 AND subject = $2",
                )
                .bind(provider)
                .bind(subject)
                .fetch_one(&mut *tx)
                .await?;
                tx.rollback().await?;
                return Ok(CreateAccount::IdentityTaken(existing));
            }
        }
        Self::insert_device_tx(&mut tx, account_id, &device, now).await?;
        tx.commit().await?;
        Ok(CreateAccount::Created)
    }

    pub async fn account_auth(&self, account_id: &str) -> Result<Option<AccountAuth>, sqlx::Error> {
        let Some(hash) = sqlx::query_scalar::<_, Vec<u8>>(
            "SELECT recovery_verifier_hash FROM accounts WHERE id = $1",
        )
        .bind(account_id)
        .fetch_optional(&self.pool)
        .await?
        else {
            return Ok(None);
        };
        let identity = sqlx::query("SELECT provider, subject FROM account_identities WHERE account_id = $1")
            .bind(account_id)
            .fetch_optional(&self.pool)
            .await?
            .map(|row| Ok::<_, sqlx::Error>((row.try_get(0)?, row.try_get(1)?)))
            .transpose()?;
        Ok(Some(AccountAuth { recovery_verifier_hash: hash, identity }))
    }

    // ----------------------------------------------------------------- devices

    async fn insert_device_tx(
        tx: &mut sqlx::Transaction<'_, sqlx::Any>,
        account_id: &str,
        device: &NewDevice<'_>,
        now: i64,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            "INSERT INTO devices (id, account_id, name, token_hash, last_cursor, last_seen_at, created_at, revoked_at) \
             VALUES ($1, $2, $3, $4, 0, $5, $5, 0)",
        )
        .bind(device.id)
        .bind(account_id)
        .bind(device.name)
        .bind(device.token_hash)
        .bind(now)
        .execute(&mut **tx)
        .await?;
        Ok(())
    }

    pub async fn insert_device(&self, account_id: &str, device: NewDevice<'_>, now: i64) -> Result<(), sqlx::Error> {
        let mut tx = self.pool.begin().await?;
        Self::insert_device_tx(&mut tx, account_id, &device, now).await?;
        tx.commit().await
    }

    pub async fn find_device_by_token_hash(&self, token_hash: &[u8]) -> Result<Option<DeviceCtx>, sqlx::Error> {
        let row = sqlx::query("SELECT id, account_id FROM devices WHERE token_hash = $1 AND revoked_at = 0")
            .bind(token_hash)
            .fetch_optional(&self.pool)
            .await?;
        row.map(|r| Ok(DeviceCtx { device_id: r.try_get(0)?, account_id: r.try_get(1)? }))
            .transpose()
    }

    pub async fn list_devices(&self, account_id: &str) -> Result<Vec<DeviceRow>, sqlx::Error> {
        let rows = sqlx::query(
            "SELECT id, name, created_at, last_seen_at FROM devices \
             WHERE account_id = $1 AND revoked_at = 0 ORDER BY created_at, id",
        )
        .bind(account_id)
        .fetch_all(&self.pool)
        .await?;
        rows.iter()
            .map(|r| {
                Ok(DeviceRow {
                    id: r.try_get(0)?,
                    name: r.try_get(1)?,
                    created_at: r.try_get(2)?,
                    last_seen_at: r.try_get(3)?,
                })
            })
            .collect()
    }

    /// Returns false if the device does not belong to the account.
    pub async fn revoke_device(&self, account_id: &str, device_id: &str, now: i64) -> Result<bool, sqlx::Error> {
        let changed = sqlx::query(
            "UPDATE devices SET revoked_at = $1 WHERE id = $2 AND account_id = $3 AND revoked_at = 0",
        )
        .bind(now)
        .bind(device_id)
        .bind(account_id)
        .execute(&self.pool)
        .await?
        .rows_affected();
        if changed > 0 {
            return Ok(true);
        }
        let exists: Option<i64> = sqlx::query_scalar("SELECT revoked_at FROM devices WHERE id = $1 AND account_id = $2")
            .bind(device_id)
            .bind(account_id)
            .fetch_optional(&self.pool)
            .await?;
        Ok(exists.is_some())
    }

    async fn touch_device(&self, device_id: &str, cursor: i64, now: i64) -> Result<(), sqlx::Error> {
        sqlx::query(
            "UPDATE devices SET last_seen_at = $1, \
             last_cursor = CASE WHEN last_cursor < $2 THEN $2 ELSE last_cursor END WHERE id = $3",
        )
        .bind(now)
        .bind(cursor)
        .bind(device_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    // ----------------------------------------------------------------- changes

    /// Stores the blocks that are newer than what is stored. Returns one outcome
    /// per block, in order, and the account's highest sequence number afterwards.
    pub async fn upsert_blocks(
        &self,
        ctx: &DeviceCtx,
        blocks: &[BlockIn],
        now: i64,
    ) -> Result<(Vec<Upsert>, i64), sqlx::Error> {
        let mut tx = self.pool.begin().await?;
        // Write first: serialises pushes per account, so seq is assigned in commit order.
        let mut next: i64 =
            sqlx::query_scalar("UPDATE accounts SET next_seq = next_seq WHERE id = $1 RETURNING next_seq")
                .bind(&ctx.account_id)
                .fetch_one(&mut *tx)
                .await?;
        let mut outcomes = Vec::with_capacity(blocks.len());
        for block in blocks {
            let stored = sqlx::query("SELECT version, seq FROM blocks WHERE account_id = $1 AND block_id = $2")
                .bind(&ctx.account_id)
                .bind(&block.block_id)
                .fetch_optional(&mut *tx)
                .await?;
            if let Some(row) = stored {
                let version: String = row.try_get(0)?;
                let seq: i64 = row.try_get(1)?;
                // Versions are fixed-width lower-case hex, so byte order is the clock order.
                match block.version.as_bytes().cmp(version.as_bytes()) {
                    std::cmp::Ordering::Less => {
                        outcomes.push(Upsert::Stale);
                        continue;
                    }
                    std::cmp::Ordering::Equal => {
                        outcomes.push(Upsert::Duplicate(seq));
                        continue;
                    }
                    std::cmp::Ordering::Greater => {}
                }
            }
            sqlx::query(
                "INSERT INTO blocks (account_id, block_id, note_id, version, deleted, nonce, ciphertext, \
                 seq, origin_device_id, received_at) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) \
                 ON CONFLICT (account_id, block_id) DO UPDATE SET note_id = excluded.note_id, \
                 version = excluded.version, deleted = excluded.deleted, nonce = excluded.nonce, \
                 ciphertext = excluded.ciphertext, seq = excluded.seq, \
                 origin_device_id = excluded.origin_device_id, received_at = excluded.received_at",
            )
            .bind(&ctx.account_id)
            .bind(&block.block_id)
            .bind(&block.note_id)
            .bind(&block.version)
            .bind(block.deleted as i64)
            .bind(&block.nonce[..])
            .bind(&block.ciphertext[..])
            .bind(next)
            .bind(&ctx.device_id)
            .bind(now)
            .execute(&mut *tx)
            .await?;
            outcomes.push(Upsert::Accepted(next));
            next += 1;
        }
        sqlx::query("UPDATE accounts SET next_seq = $1 WHERE id = $2")
            .bind(next)
            .bind(&ctx.account_id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok((outcomes, next - 1))
    }

    /// Returns `None` if the cursor is older than the history the server still has.
    pub async fn changes_since(
        &self,
        ctx: &DeviceCtx,
        since: i64,
        limit: usize,
        max_bytes: usize,
        now: i64,
    ) -> Result<Option<ChangeSlice>, sqlx::Error> {
        let gc_floor: i64 = sqlx::query_scalar("SELECT gc_floor FROM accounts WHERE id = $1")
            .bind(&ctx.account_id)
            .fetch_one(&self.pool)
            .await?;
        if since > 0 && since < gc_floor {
            return Ok(None);
        }
        let rows = sqlx::query(
            "SELECT block_id, note_id, version, deleted, nonce, ciphertext, seq, origin_device_id \
             FROM blocks WHERE account_id = $1 AND seq > $2 ORDER BY seq LIMIT $3",
        )
        .bind(&ctx.account_id)
        .bind(since)
        .bind(limit as i64 + 1)
        .fetch_all(&self.pool)
        .await?;
        let mut has_more = rows.len() > limit;
        let mut blocks = Vec::new();
        let mut bytes = 0usize;
        for row in rows.iter().take(limit) {
            let block = block_from_row(row)?;
            // Rough size of the block as JSON: base64 payload plus fixed fields.
            let size = block.block.ciphertext.len() * 4 / 3 + 320;
            if !blocks.is_empty() && bytes + size > max_bytes {
                has_more = true;
                break;
            }
            bytes += size;
            blocks.push(block);
        }
        let next_cursor = blocks.last().map(|b| b.seq).unwrap_or(since);
        self.touch_device(&ctx.device_id, since, now).await?;
        Ok(Some(ChangeSlice { blocks, next_cursor, has_more }))
    }

    // ------------------------------------------------------------------- blobs

    pub async fn blob_size(&self, account_id: &str, hash: &str) -> Result<Option<i64>, sqlx::Error> {
        sqlx::query_scalar("SELECT size FROM blobs WHERE account_id = $1 AND hash = $2")
            .bind(account_id)
            .bind(hash)
            .fetch_optional(&self.pool)
            .await
    }

    pub async fn blob_usage(&self, account_id: &str) -> Result<i64, sqlx::Error> {
        sqlx::query_scalar("SELECT CAST(COALESCE(SUM(size), 0) AS BIGINT) FROM blobs WHERE account_id = $1")
            .bind(account_id)
            .fetch_one(&self.pool)
            .await
    }

    pub async fn insert_blob(&self, account_id: &str, hash: &str, size: i64, now: i64) -> Result<(), sqlx::Error> {
        sqlx::query(
            "INSERT INTO blobs (account_id, hash, size, created_at) VALUES ($1, $2, $3, $4) \
             ON CONFLICT (account_id, hash) DO NOTHING",
        )
        .bind(account_id)
        .bind(hash)
        .bind(size)
        .bind(now)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    // ---------------------------------------------------------------- pairings

    /// Returns false if the channel is in use; the caller retries with another.
    pub async fn create_pairing(&self, p: NewPairing<'_>, now: i64) -> Result<bool, sqlx::Error> {
        sqlx::query("DELETE FROM pairings WHERE expires_at <= $1")
            .bind(now)
            .execute(&self.pool)
            .await?;
        let result = sqlx::query(
            "INSERT INTO pairings (id, channel, poll_token_hash, device_name, pake_msg_new, state, account_id, expires_at) \
             VALUES ($1, $2, $3, $4, $5, 'pending', '', $6)",
        )
        .bind(p.id)
        .bind(p.channel)
        .bind(p.poll_token_hash)
        .bind(p.device_name)
        .bind(p.pake_msg)
        .bind(p.expires_at)
        .execute(&self.pool)
        .await;
        match result {
            Ok(_) => Ok(true),
            Err(e) if is_unique_violation(&e) => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// A pairing can be claimed once. The claim binds it to the caller's account.
    pub async fn claim_pairing(
        &self,
        channel: &str,
        account_id: &str,
        now: i64,
    ) -> Result<Result<ClaimedPairing, PairingError>, sqlx::Error> {
        let row = sqlx::query(
            "UPDATE pairings SET state = 'claimed', account_id = $1 \
             WHERE channel = $2 AND state = 'pending' AND expires_at > $3 \
             RETURNING id, device_name, pake_msg_new",
        )
        .bind(account_id)
        .bind(channel)
        .bind(now)
        .fetch_optional(&self.pool)
        .await?;
        if let Some(row) = row {
            return Ok(Ok(ClaimedPairing {
                id: row.try_get(0)?,
                device_name: row.try_get(1)?,
                pake_msg: row.try_get(2)?,
            }));
        }
        let expires: Option<i64> = sqlx::query_scalar("SELECT expires_at FROM pairings WHERE channel = $1")
            .bind(channel)
            .fetch_optional(&self.pool)
            .await?;
        Ok(Err(match expires {
            None => PairingError::NotFound,
            Some(t) if t <= now => PairingError::Expired,
            Some(_) => PairingError::Conflict,
        }))
    }

    /// Only the account that claimed the pairing can approve it, and only once.
    pub async fn approve_pairing(
        &self,
        pairing_id: &str,
        account_id: &str,
        pake_msg: &[u8],
        wrapped_nonce: &[u8],
        wrapped_ciphertext: &[u8],
        now: i64,
    ) -> Result<Result<(), PairingError>, sqlx::Error> {
        let mut tx = self.pool.begin().await?;
        let changed = sqlx::query(
            "UPDATE pairings SET state = 'approved' \
             WHERE id = $1 AND account_id = $2 AND state = 'claimed' AND expires_at > $3",
        )
        .bind(pairing_id)
        .bind(account_id)
        .bind(now)
        .execute(&mut *tx)
        .await?
        .rows_affected();
        if changed == 0 {
            let row = sqlx::query("SELECT expires_at FROM pairings WHERE id = $1 AND account_id = $2")
                .bind(pairing_id)
                .bind(account_id)
                .fetch_optional(&mut *tx)
                .await?;
            tx.rollback().await?;
            return Ok(Err(match row {
                None => PairingError::NotFound,
                Some(r) if r.try_get::<i64, _>(0)? <= now => PairingError::Expired,
                Some(_) => PairingError::Conflict,
            }));
        }
        sqlx::query(
            "INSERT INTO pairing_approvals (pairing_id, pake_msg_existing, wrapped_nonce, wrapped_ciphertext) \
             VALUES ($1, $2, $3, $4)",
        )
        .bind(pairing_id)
        .bind(pake_msg)
        .bind(wrapped_nonce)
        .bind(wrapped_ciphertext)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(Ok(()))
    }

    pub async fn get_pairing(&self, pairing_id: &str) -> Result<Option<PairingRow>, sqlx::Error> {
        let row = sqlx::query("SELECT poll_token_hash, device_name, state, expires_at FROM pairings WHERE id = $1")
            .bind(pairing_id)
            .fetch_optional(&self.pool)
            .await?;
        row.map(|r| {
            Ok(PairingRow {
                poll_token_hash: r.try_get(0)?,
                device_name: r.try_get(1)?,
                state: r.try_get(2)?,
                expires_at: r.try_get(3)?,
            })
        })
        .transpose()
    }

    /// Hands out an approved pairing exactly once: deletes it and creates the device.
    /// Returns `None` if another request already took it.
    pub async fn deliver_pairing(
        &self,
        pairing_id: &str,
        device: NewDevice<'_>,
        now: i64,
    ) -> Result<Option<Approval>, sqlx::Error> {
        let mut tx = self.pool.begin().await?;
        let account_id: Option<String> = sqlx::query_scalar(
            "DELETE FROM pairings WHERE id = $1 AND state = 'approved' AND expires_at > $2 RETURNING account_id",
        )
        .bind(pairing_id)
        .bind(now)
        .fetch_optional(&mut *tx)
        .await?;
        let Some(account_id) = account_id else {
            tx.rollback().await?;
            return Ok(None);
        };
        let row = sqlx::query(
            "DELETE FROM pairing_approvals WHERE pairing_id = $1 \
             RETURNING pake_msg_existing, wrapped_nonce, wrapped_ciphertext",
        )
        .bind(pairing_id)
        .fetch_one(&mut *tx)
        .await?;
        let approval = Approval {
            account_id,
            pake_msg: row.try_get(0)?,
            wrapped_nonce: row.try_get(1)?,
            wrapped_ciphertext: row.try_get(2)?,
        };
        Self::insert_device_tx(&mut tx, &approval.account_id, &device, now).await?;
        tx.commit().await?;
        Ok(Some(approval))
    }

    // ------------------------------------------------------------- OIDC nonces

    pub async fn insert_oidc_nonce(&self, nonce_hash: &[u8], provider: &str, expires_at: i64) -> Result<(), sqlx::Error> {
        sqlx::query("INSERT INTO oidc_nonces (nonce_hash, provider, expires_at) VALUES ($1, $2, $3)")
            .bind(nonce_hash)
            .bind(provider)
            .bind(expires_at)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Single use: returns true exactly once per valid nonce.
    pub async fn consume_oidc_nonce(&self, nonce_hash: &[u8], provider: &str, now: i64) -> Result<bool, sqlx::Error> {
        let deleted = sqlx::query("DELETE FROM oidc_nonces WHERE nonce_hash = $1 AND provider = $2 AND expires_at > $3")
            .bind(nonce_hash)
            .bind(provider)
            .bind(now)
            .execute(&self.pool)
            .await?
            .rows_affected();
        Ok(deleted == 1)
    }

    // ---------------------------------------------------------------- clean-up

    pub async fn gc_expired(&self, now: i64) -> Result<(), sqlx::Error> {
        sqlx::query("DELETE FROM pairings WHERE expires_at <= $1")
            .bind(now)
            .execute(&self.pool)
            .await?;
        sqlx::query("DELETE FROM pairing_approvals WHERE pairing_id NOT IN (SELECT id FROM pairings)")
            .execute(&self.pool)
            .await?;
        sqlx::query("DELETE FROM oidc_nonces WHERE expires_at <= $1")
            .bind(now)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Removes deletion markers that every recently active device has already seen.
    /// A device that was away longer gets `cursor_expired` and resyncs.
    pub async fn gc_tombstones(&self, tombstone_cutoff: i64, device_cutoff: i64) -> Result<u64, sqlx::Error> {
        let accounts: Vec<String> = sqlx::query_scalar(
            "SELECT DISTINCT account_id FROM blocks WHERE deleted = 1 AND received_at < $1",
        )
        .bind(tombstone_cutoff)
        .fetch_all(&self.pool)
        .await?;
        let mut removed = 0;
        for account_id in accounts {
            let mut tx = self.pool.begin().await?;
            sqlx::query("UPDATE accounts SET gc_floor = gc_floor WHERE id = $1")
                .bind(&account_id)
                .execute(&mut *tx)
                .await?;
            let min_cursor: i64 = sqlx::query_scalar(
                "SELECT CAST(COALESCE(MIN(last_cursor), 0) AS BIGINT) FROM devices \
                 WHERE account_id = $1 AND revoked_at = 0 AND last_seen_at > $2",
            )
            .bind(&account_id)
            .bind(device_cutoff)
            .fetch_one(&mut *tx)
            .await?;
            let max_seq: i64 = sqlx::query_scalar(
                "SELECT CAST(COALESCE(MAX(seq), 0) AS BIGINT) FROM blocks \
                 WHERE account_id = $1 AND deleted = 1 AND seq <= $2 AND received_at < $3",
            )
            .bind(&account_id)
            .bind(min_cursor)
            .bind(tombstone_cutoff)
            .fetch_one(&mut *tx)
            .await?;
            if max_seq > 0 {
                removed += sqlx::query(
                    "DELETE FROM blocks WHERE account_id = $1 AND deleted = 1 AND seq <= $2 AND received_at < $3",
                )
                .bind(&account_id)
                .bind(max_seq)
                .bind(tombstone_cutoff)
                .execute(&mut *tx)
                .await?
                .rows_affected();
                sqlx::query("UPDATE accounts SET gc_floor = $1 WHERE id = $2 AND gc_floor < $1")
                    .bind(max_seq)
                    .bind(&account_id)
                    .execute(&mut *tx)
                    .await?;
            }
            tx.commit().await?;
        }
        Ok(removed)
    }
}
