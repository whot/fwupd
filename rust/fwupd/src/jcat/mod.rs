/*
 * Copyright 2026 Red Hat
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

//! JCat (JSON catalog) signature verification library.
//!
//! JCat files associate firmware images with their checksums and cryptographic
//! signatures. A `.jcat` file is gzip-compressed JSON containing one or more
//! [`Item`]s, each identified by a filename. Every item holds [`Blob`]s that
//! are either checksums (SHA-256, SHA-512) or detached signatures (PKCS#7).
//!
//! # File format
//!
//! A JCat file looks like this when decompressed:
//!
//! ```json
//! {
//!   "JcatVersionMajor": 0,
//!   "JcatVersionMinor": 1,
//!   "Items": [
//!     {
//!       "Id": "firmware.bin",
//!       "Blobs": [
//!         {
//!           "Kind": 1,
//!           "Flags": 1,
//!           "Data": "a948904f2f0f479b8f8197694b30184b0d2ed1c1cd2a1ec0fb85d299a192a447"
//!         },
//!         {
//!           "Kind": 3,
//!           "Flags": 1,
//!           "Timestamp": 1502871248,
//!           "Data": "-----BEGIN PKCS7-----\n..."
//!         }
//!       ]
//!     }
//!   ]
//! }
//! ```
//!
//! `Kind` values correspond to [`BlobKind`] (1 = SHA-256, 3 = PKCS#7, etc.).
//! `Flags` corresponds to [`BlobFlags`] — e.g. [`BlobFlags::IS_UTF8`] (1) means
//! the data is UTF-8 text; 0 means it is base64-encoded binary.
//!
//! # Verification
//!
//! Verification is two-phase:
//! - **All** checksum blobs must pass (any failure is fatal).
//! - **At least one** signature blob must pass (individual failures are
//!   not fatal as long as one succeeds).
//!
//! # Usage
//!
//! ```no_run
//! use fwupd::jcat::{ContextBuilder, File, BlobKind, VerifyFlags};
//! use std::path::Path;
//!
//! // Load a .jcat file
//! let jcat_bytes = std::fs::read("firmware.jcat").unwrap();
//! let jcat_file = File::new_from_bytes(&jcat_bytes).unwrap();
//!
//! // Set up a verification context
//! let mut ctx = ContextBuilder::new()
//!     .allow_blob_kind(&[BlobKind::Sha256, BlobKind::Pkcs7])
//!     .public_keys(Path::new("/etc/pki/fwupd"))
//!     .build();
//!
//! // Verify firmware against the JCat item
//! let firmware = std::fs::read("firmware.bin").unwrap();
//! let item = jcat_file.item_by_id("firmware.bin").unwrap();
//! let results = ctx.verify_item(
//!     &firmware,
//!     item,
//!     VerifyFlags::REQUIRE_CHECKSUM | VerifyFlags::REQUIRE_SIGNATURE,
//! ).unwrap();
//!
//! for result in &results {
//!     println!("verified by {} ({}) ", result.kind(), result.method());
//! }
//! ```

mod blob;
mod context;
mod engine;
mod error;
mod file;
mod item;
mod result;
mod types;

pub use blob::{Blob, BlobData};
pub use context::{Context, ContextBuilder};
pub use engine::Engine;
pub use error::Error;
pub use file::{File, Version};
pub use item::Item;
pub use result::VerifyResult;
pub use types::{BlobFlags, BlobKind, BlobMethod, SignFlags, VerifyFlags};
