//! The shared client core talking to the real server.
//!
//! Each "device" is a `notes_core::Core` on an in-memory platform whose HTTP
//! port calls the server's router directly. This is the test of the protocol
//! as a whole: what one device writes, another one can read, and the server
//! in between can neither read nor change it.

mod common;

use axum::body::Body;
use axum::http::Method;
use common::*;
use notes_core::hal::{
    Entropy, FileStore, HalError, HttpRequest, HttpResponse, HttpTransport, NetworkMonitor, SecureStore, TimeSource,
};
use notes_core::Core;
use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::rc::Rc;

const SERVER: &str = "https://notes.test";

/// What survives a restart of the app on one device.
#[derive(Default)]
struct Disk {
    files: RefCell<BTreeMap<String, Vec<u8>>>,
    secrets: RefCell<BTreeMap<String, Vec<u8>>>,
}

struct TestPlatform<'a> {
    app: &'a TestApp,
    disk: Rc<Disk>,
    online: Rc<Cell<bool>>,
    clock_offset_ms: Rc<Cell<i64>>,
}

impl HttpTransport for TestPlatform<'_> {
    async fn send(&self, request: HttpRequest) -> Result<HttpResponse, HalError> {
        let path = request.url.strip_prefix(SERVER).ok_or_else(|| HalError("unexpected host".into()))?;
        let headers: Vec<(&str, &str)> = request.headers.iter().map(|(n, v)| (*n, v.as_str())).collect();
        let method = Method::from_bytes(request.method.as_bytes()).unwrap();
        let body = request.body.map(Body::from).unwrap_or_else(Body::empty);
        let (status, response_headers, body) = self.app.send(None, method, path, None, &headers, body).await;
        Ok(HttpResponse {
            status: status.as_u16(),
            headers: response_headers
                .iter()
                .map(|(n, v)| (n.as_str().to_string(), v.to_str().unwrap_or("").to_string()))
                .collect(),
            body,
        })
    }
}

impl FileStore for TestPlatform<'_> {
    async fn file_read(&self, name: &str) -> Result<Option<Vec<u8>>, HalError> {
        Ok(self.disk.files.borrow().get(name).cloned())
    }
    async fn file_write(&self, name: &str, data: &[u8]) -> Result<(), HalError> {
        self.disk.files.borrow_mut().insert(name.into(), data.to_vec());
        Ok(())
    }
    async fn file_remove(&self, name: &str) -> Result<(), HalError> {
        self.disk.files.borrow_mut().remove(name);
        Ok(())
    }
    async fn file_list(&self, prefix: &str) -> Result<Vec<String>, HalError> {
        Ok(self.disk.files.borrow().keys().filter(|k| k.starts_with(prefix)).cloned().collect())
    }
}

impl SecureStore for TestPlatform<'_> {
    async fn secret_get(&self, name: &str) -> Result<Option<Vec<u8>>, HalError> {
        Ok(self.disk.secrets.borrow().get(name).cloned())
    }
    async fn secret_put(&self, name: &str, data: &[u8]) -> Result<(), HalError> {
        self.disk.secrets.borrow_mut().insert(name.into(), data.to_vec());
        Ok(())
    }
    async fn secret_remove(&self, name: &str) -> Result<(), HalError> {
        self.disk.secrets.borrow_mut().remove(name);
        Ok(())
    }
}

impl TimeSource for TestPlatform<'_> {
    fn now_ms(&self) -> i64 {
        now_ms() + self.clock_offset_ms.get()
    }
}

impl NetworkMonitor for TestPlatform<'_> {
    fn is_online(&self) -> bool {
        self.online.get()
    }
}

impl Entropy for TestPlatform<'_> {
    fn fill_random(&self, buffer: &mut [u8]) -> Result<(), HalError> {
        for chunk in buffer.chunks_mut(32) {
            chunk.copy_from_slice(&notes_syncd::util::random_bytes::<32>()[..chunk.len()]);
        }
        Ok(())
    }
}

struct Device<'a> {
    core: Core<TestPlatform<'a>>,
    disk: Rc<Disk>,
    online: Rc<Cell<bool>>,
    clock_offset_ms: Rc<Cell<i64>>,
}

async fn device_on<'a>(app: &'a TestApp, disk: Rc<Disk>) -> Device<'a> {
    let online = Rc::new(Cell::new(true));
    let clock_offset_ms = Rc::new(Cell::new(0));
    let platform =
        TestPlatform { app, disk: disk.clone(), online: online.clone(), clock_offset_ms: clock_offset_ms.clone() };
    Device { core: Core::open(platform).await.unwrap(), disk, online, clock_offset_ms }
}

async fn device(app: &TestApp) -> Device<'_> {
    device_on(app, Rc::new(Disk::default())).await
}

fn texts(device: &Device<'_>, note_id: &str) -> Vec<String> {
    device.core.get_note(note_id).map(|n| n.blocks.into_iter().map(|b| b.text).collect()).unwrap_or_default()
}

#[tokio::test]
async fn two_devices_share_notes_and_the_server_sees_only_ciphertext() {
    let app = app().await;
    let laptop = device(&app).await;
    let kit = laptop.core.create_account(SERVER, INVITE, "laptop").await.unwrap();
    assert_eq!(kit.phrase.split(' ').count(), 24);

    let note = laptop.core.create_note("").await.unwrap();
    laptop.core.set_title(&note.note_id, "Shopping list for Saturday").await.unwrap();
    let first = &note.blocks[0];
    laptop.core.update_block(&first.block_id, "todo", "sourdough bread", BTreeMap::new()).await.unwrap();
    let second = laptop.core.insert_block(&note.note_id, Some(&first.block_id), "todo", "oat milk").await.unwrap();
    laptop.core.insert_block(&note.note_id, Some(&first.block_id), "paragraph", "in between").await.unwrap();
    laptop.core.insert_block(&note.note_id, None, "heading", "on top").await.unwrap();
    assert_eq!(texts(&laptop, &note.note_id), ["on top", "sourdough bread", "in between", "oat milk"]);
    assert_eq!(laptop.core.status().pending, 5);

    let report = laptop.core.sync().await.unwrap();
    assert_eq!((report.pushed, report.pulled), (5, 0));
    assert_eq!(laptop.core.status().pending, 0);

    // A second device joins with the recovery kit and sees the same note.
    let phone = device(&app).await;
    phone.core.recover(SERVER, &kit.account_id, &kit.phrase, "phone").await.unwrap();
    let report = phone.core.sync().await.unwrap();
    assert_eq!(report.pulled, 5);
    assert_eq!(report.changed_notes, std::slice::from_ref(&note.note_id));
    assert_eq!(texts(&phone, &note.note_id), ["on top", "sourdough bread", "in between", "oat milk"]);
    let listed = phone.core.list_notes();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].title, "Shopping list for Saturday");
    assert_eq!(listed[0].preview, "on top");

    // Changes travel in both directions, deletions included.
    let mut done = BTreeMap::new();
    done.insert("done".to_string(), "true".to_string());
    phone.core.update_block(&second.block_id, "todo", "oat milk", done.clone()).await.unwrap();
    phone.core.delete_block(&first.block_id).await.unwrap();
    phone.core.sync().await.unwrap();
    let report = laptop.core.sync().await.unwrap();
    assert_eq!(report.pulled, 2);
    assert_eq!(texts(&laptop, &note.note_id), ["on top", "in between", "oat milk"]);
    let view = laptop.core.get_note(&note.note_id).unwrap();
    assert_eq!(view.blocks[2].attrs, done);

    // Nothing the server stores, and nothing on the device's disk, contains
    // a word of the note.
    let haystacks: Vec<Vec<u8>> = {
        let mut all = Vec::new();
        for entry in walk(app.state.config.server.data_dir.as_path()) {
            all.push(std::fs::read(entry).unwrap());
        }
        all.extend(laptop.disk.files.borrow().values().cloned());
        all
    };
    assert!(!haystacks.is_empty());
    for needle in ["Shopping", "sourdough", "oat milk", "in between", "todo", "paragraph"] {
        assert!(
            !haystacks.iter().any(|h| h.windows(needle.len()).any(|w| w == needle.as_bytes())),
            "\"{needle}\" found in stored data"
        );
    }

    // Deleting the note removes it everywhere.
    laptop.core.delete_note(&note.note_id).await.unwrap();
    laptop.core.sync().await.unwrap();
    phone.core.sync().await.unwrap();
    assert!(phone.core.list_notes().is_empty());
    assert!(phone.core.get_note(&note.note_id).is_none());
}

fn walk(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut files = Vec::new();
    for entry in std::fs::read_dir(dir).into_iter().flatten().flatten() {
        let path = entry.path();
        if path.is_dir() {
            files.extend(walk(&path));
        } else {
            files.push(path);
        }
    }
    files
}

#[tokio::test]
async fn the_later_edit_of_a_block_wins_and_other_blocks_merge() {
    let app = app().await;
    let a = device(&app).await;
    let kit = a.core.create_account(SERVER, INVITE, "a").await.unwrap();
    let note = a.core.create_note("").await.unwrap();
    let shared = note.blocks[0].block_id.clone();
    a.core.update_block(&shared, "paragraph", "original", BTreeMap::new()).await.unwrap();
    a.core.sync().await.unwrap();
    let b = device(&app).await;
    b.core.recover(SERVER, &kit.account_id, &kit.phrase, "b").await.unwrap();
    b.core.sync().await.unwrap();

    // Both edit the same block while offline, and each adds one of its own.
    a.online.set(false);
    b.online.set(false);
    assert_eq!(a.core.sync().await.err().unwrap().code, "offline");
    a.core.update_block(&shared, "paragraph", "edited on a", BTreeMap::new()).await.unwrap();
    a.core.insert_block(&note.note_id, Some(&shared), "paragraph", "added on a").await.unwrap();
    b.clock_offset_ms.set(5_000);
    b.core.update_block(&shared, "paragraph", "edited on b, later", BTreeMap::new()).await.unwrap();
    b.core.insert_block(&note.note_id, Some(&shared), "paragraph", "added on b").await.unwrap();

    a.online.set(true);
    b.online.set(true);
    a.core.sync().await.unwrap();
    b.core.sync().await.unwrap();
    a.core.sync().await.unwrap();

    let on_a = texts(&a, &note.note_id);
    assert_eq!(on_a, texts(&b, &note.note_id), "both devices converge");
    assert_eq!(on_a[0], "edited on b, later");
    assert_eq!(on_a.len(), 3);
    assert!(on_a.contains(&"added on a".to_string()) && on_a.contains(&"added on b".to_string()));
    assert_eq!(a.core.status().pending + b.core.status().pending, 0);
}

#[tokio::test]
async fn state_survives_a_restart_and_unsent_changes_are_sent_later() {
    let app = app().await;
    let first_run = device(&app).await;
    first_run.core.create_account(SERVER, INVITE, "laptop").await.unwrap();
    let note = first_run.core.create_note("").await.unwrap();
    first_run.core.set_title(&note.note_id, "written before the restart").await.unwrap();
    first_run.core.sync().await.unwrap();
    first_run.online.set(false);
    first_run.core.update_block(&note.blocks[0].block_id, "paragraph", "not uploaded yet", BTreeMap::new()).await.unwrap();
    let disk = first_run.disk.clone();
    drop(first_run);

    let second_run = device_on(&app, disk).await;
    let status = second_run.core.status();
    assert!(status.signed_in);
    assert_eq!((status.notes, status.pending), (1, 1));
    assert_eq!(second_run.core.list_notes()[0].title, "written before the restart");
    assert_eq!(texts(&second_run, &note.note_id), ["not uploaded yet"]);
    let report = second_run.core.sync().await.unwrap();
    assert_eq!((report.pushed, report.pulled), (1, 0));

    // Signing out leaves nothing behind on the device and revokes its token.
    let token_worked = second_run.core.list_devices().await.unwrap().len();
    assert_eq!(token_worked, 1);
    second_run.core.sign_out(true).await.unwrap();
    assert!(second_run.disk.files.borrow().is_empty() && second_run.disk.secrets.borrow().is_empty());
    assert!(!second_run.core.status().signed_in);
    assert_eq!(second_run.core.create_note("").await.err().unwrap().code, "not_signed_in");
}

#[tokio::test]
async fn a_tampering_server_or_disk_is_detected() {
    let app = app().await;
    let a = device(&app).await;
    let kit = a.core.create_account(SERVER, INVITE, "a").await.unwrap();
    let note = a.core.create_note("").await.unwrap();
    a.core.update_block(&note.blocks[0].block_id, "paragraph", "the real text", BTreeMap::new()).await.unwrap();
    a.core.sync().await.unwrap();

    // The server operator rewrites history: the block's ciphertext is
    // replaced by the header's, under a higher version.
    let account = a.core.status().account_id;
    let pool = app.state.store.pool();
    sqlx::query("UPDATE blocks SET version = $1 WHERE account_id = $2")
        .bind(version(now_ms() + 1000, 0))
        .bind(&account)
        .execute(pool)
        .await
        .unwrap();

    let b = device(&app).await;
    b.core.recover(SERVER, &kit.account_id, &kit.phrase, "b").await.unwrap();
    let report = b.core.sync().await.unwrap();
    assert_eq!((report.pulled, report.undecryptable), (0, 2));
    assert!(b.core.list_notes().is_empty(), "forged blocks are not shown");

    // A wrong phrase never gets a device, and says so without contacting
    // the account.
    let c = device(&app).await;
    let mut words: Vec<&str> = kit.phrase.split(' ').collect();
    let other = (1..24).find(|i| words[*i] != words[0]).unwrap();
    words.swap(0, other);
    assert_eq!(c.core.recover(SERVER, &kit.account_id, &words.join(" "), "c").await.err().unwrap().code, "bad_phrase");
    assert_eq!(c.core.create_account(SERVER, "wrong-invite-code-000000", "c").await.err().unwrap().code, "invalid_invite");
    assert_eq!(c.core.create_account("http://example.com", INVITE, "c").await.err().unwrap().code, "input");

    // Someone edits the device's storage: the changed block is dropped at
    // the next start instead of being shown.
    let disk = a.disk.clone();
    drop(a);
    {
        let mut files = disk.files.borrow_mut();
        let name = format!("block/{}", note.blocks[0].block_id);
        let raw = files.get(&name).cloned().unwrap();
        let mut stored: serde_json::Value = serde_json::from_slice(&raw).unwrap();
        stored["envelope"]["deleted"] = serde_json::json!(true);
        files.insert(name, serde_json::to_vec(&stored).unwrap());
    }
    let reopened = device_on(&app, disk).await;
    let after = reopened.core.get_note(&note.note_id).expect("the untouched header is still there");
    assert!(after.blocks.is_empty(), "the altered block failed authentication and is not shown");
}

#[tokio::test]
async fn a_device_that_was_away_too_long_resyncs_from_scratch() {
    let app = app().await;
    let a = device(&app).await;
    let kit = a.core.create_account(SERVER, INVITE, "a").await.unwrap();
    let keep = a.core.create_note("").await.unwrap();
    a.core.set_title(&keep.note_id, "stays").await.unwrap();
    let gone = a.core.create_note("").await.unwrap();
    a.core.set_title(&gone.note_id, "will be deleted").await.unwrap();
    a.core.sync().await.unwrap();

    let sleeper = device(&app).await;
    sleeper.core.recover(SERVER, &kit.account_id, &kit.phrase, "sleeper").await.unwrap();
    sleeper.core.sync().await.unwrap();
    assert_eq!(sleeper.core.list_notes().len(), 2);
    let unsent = sleeper.core.create_note("").await.unwrap();
    sleeper.core.set_title(&unsent.note_id, "written while away").await.unwrap();
    sleeper.online.set(false);

    // Meanwhile the note is deleted, and the server forgets the deletion
    // markers because the sleeper counts as inactive.
    a.core.delete_note(&gone.note_id).await.unwrap();
    a.core.sync().await.unwrap();
    a.core.sync().await.unwrap();
    sqlx::query("UPDATE devices SET last_seen_at = 1 WHERE id = $1")
        .bind(sleeper.core.status().device_id)
        .execute(app.state.store.pool())
        .await
        .unwrap();
    assert_eq!(app.state.store.gc_tombstones(now_ms() + 3_600_000, 2).await.unwrap(), 2);

    sleeper.online.set(true);
    let report = sleeper.core.sync().await.unwrap();
    assert!(report.full_resync);
    let titles: Vec<String> = sleeper.core.list_notes().into_iter().map(|n| n.title).collect();
    assert_eq!(titles.len(), 2, "{titles:?}");
    assert!(titles.contains(&"stays".to_string()) && titles.contains(&"written while away".to_string()));
    a.core.sync().await.unwrap();
    assert_eq!(a.core.list_notes().len(), 2);
}

#[tokio::test]
async fn attachments_travel_encrypted_and_are_checked_on_arrival() {
    let app = app().await;
    let a = device(&app).await;
    let kit = a.create_account(SERVER, INVITE, "first").await.unwrap();
    let note = a.create_note("").await.unwrap();
    // Larger than one chunk, so the chunking is exercised as well.
    let file: Vec<u8> = (0..150_000u32).map(|i| (i % 251) as u8).collect();
    let block = a.add_attachment(&note.note_id, None, " photo.png ", "Image/PNG", &file).await.unwrap();
    assert_eq!(block.kind, "attachment");
    assert_eq!(block.text, "photo.png");
    assert_eq!(block.attrs["mime"], "image/png");
    assert_eq!(block.attrs["size"], "150000");
    assert_eq!(a.attachment(&block.block_id).await.unwrap(), file);

    // The file cannot be swapped under an existing attachment block.
    let mut attrs = block.attrs.clone();
    attrs.insert("hash".into(), "0".repeat(64));
    assert_eq!(a.update_block(&block.block_id, "attachment", "x", attrs).await.err().unwrap().code, "input");
    assert_eq!(a.insert_block(&note.note_id, None, "attachment", "x").await.err().unwrap().code, "input");
    let big = vec![0u8; notes_core::MAX_ATTACHMENT_BYTES + 1];
    assert_eq!(a.add_attachment(&note.note_id, None, "big", "x/y", &big).await.err().unwrap().code, "too_large");

    a.sync().await.unwrap();
    // On the server: one blob, and nothing of the file in the clear.
    let blobs: Vec<_> = walk(&app.state.config.server.data_dir.join("blobs")).into_iter().collect();
    assert_eq!(blobs.len(), 1);
    let stored = std::fs::read(&blobs[0]).unwrap();
    assert!(stored.len() > file.len());
    assert!(!stored.windows(64).any(|w| w == &file[..64]));

    let b = device(&app).await;
    b.recover(SERVER, &kit.account_id, &kit.phrase, "second").await.unwrap();
    b.sync().await.unwrap();
    let seen = b.get_note(&note.note_id).unwrap();
    assert_eq!(seen.blocks[0].block_id, block.block_id);
    assert_eq!(b.attachment(&block.block_id).await.unwrap(), file);
    // The second read comes from the device's own (encrypted) copy.
    b.platform().online.set(false);
    assert_eq!(b.attachment(&block.block_id).await.unwrap(), file);
    b.platform().online.set(true);

    // A server that changes the blob is caught by a device that has no copy.
    let mut damaged = stored.clone();
    damaged[1000] ^= 1;
    std::fs::write(&blobs[0], &damaged).unwrap();
    let c = device(&app).await;
    c.recover(SERVER, &kit.account_id, &kit.phrase, "third").await.unwrap();
    c.sync().await.unwrap();
    assert_eq!(c.attachment(&block.block_id).await.err().unwrap().code, "corrupt");
    std::fs::write(&blobs[0], &stored).unwrap();
    assert_eq!(c.attachment(&block.block_id).await.unwrap(), file);

    // Deleting the block removes the local copy on every device.
    a.delete_block(&block.block_id).await.unwrap();
    a.sync().await.unwrap();
    b.sync().await.unwrap();
    for device in [&a, &b] {
        assert!(device.platform().disk.files.borrow().keys().all(|name| !name.starts_with("blob/")));
        assert_eq!(device.attachment(&block.block_id).await.err().unwrap().code, "not_found");
    }
}

#[tokio::test]
async fn folders_are_part_of_the_note_and_sync_with_it() {
    let app = app().await;
    let a = device(&app).await;
    let kit = a.create_account(SERVER, INVITE, "first").await.unwrap();
    let note = a.create_note("  Work // Plans/ ").await.unwrap();
    assert_eq!(note.folder, "Work/Plans");
    let loose = a.create_note("").await.unwrap();
    a.set_title(&note.note_id, "Roadmap").await.unwrap();
    a.sync().await.unwrap();

    let b = device(&app).await;
    b.recover(SERVER, &kit.account_id, &kit.phrase, "second").await.unwrap();
    b.sync().await.unwrap();
    let folder_of = |device: &Device<'_>, id: &str| {
        device.list_notes().into_iter().find(|n| n.note_id == id).unwrap().folder
    };
    assert_eq!(folder_of(&b, &note.note_id), "Work/Plans");
    assert_eq!(folder_of(&b, &loose.note_id), "");

    // Moving keeps the title; taking a note out of its folder works too.
    b.set_folder(&note.note_id, "Archive").await.unwrap();
    b.set_folder(&loose.note_id, "Work").await.unwrap();
    b.sync().await.unwrap();
    a.sync().await.unwrap();
    assert_eq!(folder_of(&a, &note.note_id), "Archive");
    assert_eq!(a.get_note(&note.note_id).unwrap().title, "Roadmap");
    assert_eq!(folder_of(&a, &loose.note_id), "Work");
    a.set_folder(&loose.note_id, " / ").await.unwrap();
    assert_eq!(folder_of(&a, &loose.note_id), "");
    assert_eq!(a.set_folder(&loose.note_id, &"x".repeat(300)).await.err().unwrap().code, "input");
}

#[tokio::test]
async fn blocks_can_be_moved_and_attachments_restyled() {
    let app = app().await;
    let a = device(&app).await;
    let kit = a.create_account(SERVER, INVITE, "first").await.unwrap();
    let note = a.create_note("").await.unwrap();
    let one = note.blocks[0].block_id.clone();
    a.update_block(&one, "paragraph", "one", BTreeMap::new()).await.unwrap();
    let two = a.insert_block(&note.note_id, Some(&one), "paragraph", "two").await.unwrap().block_id;
    let pic = a.add_attachment(&note.note_id, Some(&two), "pic.png", "image/png", b"not really a png").await.unwrap();

    a.move_block(&pic.block_id, None).await.unwrap();
    assert_eq!(texts(&a, &note.note_id), ["pic.png", "one", "two"]);
    a.move_block(&one, Some(&two)).await.unwrap();
    assert_eq!(texts(&a, &note.note_id), ["pic.png", "two", "one"]);
    a.move_block(&pic.block_id, Some(&two)).await.unwrap();
    assert_eq!(texts(&a, &note.note_id), ["two", "pic.png", "one"]);
    // Behind itself, or behind a block that is gone: nothing breaks.
    a.move_block(&two, Some(&two)).await.unwrap();
    a.move_block(&two, Some("00000000-0000-4000-8000-000000000000")).await.unwrap();
    assert_eq!(texts(&a, &note.note_id), ["pic.png", "one", "two"]);

    // How an attachment is shown may change; which file it is may not.
    let mut attrs = pic.attrs.clone();
    attrs.insert("width".into(), "40".into());
    attrs.insert("caption".into(), "hidden".into());
    a.update_block(&pic.block_id, "attachment", "pic.png", attrs.clone()).await.unwrap();
    attrs.insert("mime".into(), "text/html".into());
    assert_eq!(a.update_block(&pic.block_id, "attachment", "pic.png", attrs).await.err().unwrap().code, "input");

    a.sync().await.unwrap();
    let b = device(&app).await;
    b.recover(SERVER, &kit.account_id, &kit.phrase, "second").await.unwrap();
    b.sync().await.unwrap();
    assert_eq!(texts(&b, &note.note_id), ["pic.png", "one", "two"]);
    let seen = b.get_note(&note.note_id).unwrap();
    assert_eq!(seen.blocks[0].attrs["width"], "40");
    assert_eq!(b.attachment(&seen.blocks[0].block_id).await.unwrap(), b"not really a png");
}

impl<'a> std::ops::Deref for Device<'a> {
    type Target = Core<TestPlatform<'a>>;
    fn deref(&self) -> &Self::Target {
        &self.core
    }
}
