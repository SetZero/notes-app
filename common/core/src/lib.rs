//! The shared core of the notes app.
//!
//! Everything that is the same on every platform lives here: keys and
//! encryption, the note model, and sync with the server. A platform provides
//! the six ports in [`hal`] and a user interface on top of [`Core`].
//!
//! `no_std` with `alloc`, so that it also builds for the embedded device.
#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod crypto;
mod engine;
pub mod hal;
pub mod hlc;
pub mod ids;
pub mod order;

pub use engine::{
    BlockView, Core, CoreError, DeviceInfo, EventsRequest, NoteSummary, NoteView, RecoveryKit,
    Status, SyncReport, MAX_ATTACHMENT_BYTES, MAX_BLOCK_TEXT_BYTES,
};
