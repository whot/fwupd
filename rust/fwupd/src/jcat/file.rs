/*
 * Copyright 2026 Red Hat
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

//! JCat file — a collection of items stored as gzip-compressed JSON.

use flate2::Compression;
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};

use super::error::Error;
use super::item::Item;

/// A JCat file containing items with their associated blobs.
///
/// The on-disk format is gzip-compressed JSON with a version header.
///
/// # Example
///
/// ```
/// use fwupd::jcat::{File, Item, Blob, BlobKind};
///
/// // Build a file from scratch
/// let mut file = File::new();
/// let mut item = Item::new("firmware.bin");
/// item.add_blobs([Blob::new_utf8(BlobKind::Sha256, "abcdef...")]);
/// file.add_items([item]);
///
/// // Export and re-import
/// let compressed = file.export_bytes().unwrap();
/// let file2 = File::new_from_bytes(&compressed).unwrap();
/// assert_eq!(file2.items().len(), 1);
/// ```
#[derive(Debug, Clone)]
pub struct File {
    version_major: u32,
    version_minor: u32,
    items: Vec<Item>,
}

/// JSON representation of the file.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct FileJson {
    jcat_version_major: u32,
    jcat_version_minor: u32,
    items: Vec<Item>,
}

impl File {
    /// Create a new, empty JCat file.
    pub fn new() -> Self {
        Self {
            version_major: 0,
            version_minor: 1,
            items: Vec::new(),
        }
    }

    /// Create a JCat file from gzip-compressed bytes.
    pub fn new_from_bytes(data: &[u8]) -> Result<Self, Error> {
        let mut decoder = GzDecoder::new(data);
        let mut json_str = String::new();
        decoder.read_to_string(&mut json_str)?;
        Self::new_from_json(&json_str)
    }

    /// Create a JCat file from a JSON string.
    pub fn new_from_json(json: &str) -> Result<Self, Error> {
        let parsed: FileJson = serde_json::from_str(json)?;
        Ok(Self {
            version_major: parsed.jcat_version_major,
            version_minor: parsed.jcat_version_minor,
            items: parsed.items,
        })
    }

    /// Create a JCat file from a [`Read`] source containing gzip-compressed data.
    pub fn new_from_stream<R: Read>(reader: R) -> Result<Self, Error> {
        let mut decoder = GzDecoder::new(reader);
        let mut json_str = String::new();
        decoder.read_to_string(&mut json_str)?;
        Self::new_from_json(&json_str)
    }

    /// Export to gzip-compressed bytes.
    pub fn export_bytes(&self) -> Result<Vec<u8>, Error> {
        let json = self.export_json()?;
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(json.as_bytes())?;
        Ok(encoder.finish()?)
    }

    /// Export to a pretty-printed JSON string.
    pub fn export_json(&self) -> Result<String, Error> {
        let file_json = FileJson {
            jcat_version_major: self.version_major,
            jcat_version_minor: self.version_minor,
            items: self.items.clone(),
        };
        Ok(serde_json::to_string_pretty(&file_json)?)
    }

    /// Returns all items.
    pub fn items(&self) -> &[Item] {
        &self.items
    }

    /// Add one or more items.
    pub fn add_items(&mut self, items: impl IntoIterator<Item = Item>) {
        self.items.extend(items);
    }

    /// Find an item by its ID, falling back to alias IDs.
    pub fn item_by_id(&self, id: &str) -> Result<&Item, Error> {
        // Exact ID match — but check for duplicates.
        let mut found: Option<&Item> = None;
        for item in &self.items {
            if item.id() == id {
                if found.is_some() {
                    return Err(Error::NotSupported(format!("multiple matches for {id}")));
                }
                found = Some(item);
            }
        }
        if let Some(item) = found {
            return Ok(item);
        }

        // Try alias IDs.
        found = None;
        for item in &self.items {
            for alias in item.alias_ids() {
                if alias == id {
                    if found.is_some() {
                        return Err(Error::NotSupported(format!("multiple aliases for {id}")));
                    }
                    found = Some(item);
                }
            }
        }
        found.ok_or_else(|| Error::NotFound(format!("failed to find {id}")))
    }

    /// Get the default (single) item, or error if there are zero or multiple.
    pub fn item_default(&self) -> Result<&Item, Error> {
        match self.items.len() {
            0 => Err(Error::NotFound("no items found".into())),
            1 => Ok(&self.items[0]),
            _ => Err(Error::NotSupported(
                "multiple items found, no default possible".into(),
            )),
        }
    }

    /// Returns the file format version.
    pub fn version(&self) -> Version {
        Version {
            major: self.version_major,
            minor: self.version_minor,
        }
    }
}

/// JCat file format version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Version {
    pub major: u32,
    pub minor: u32,
}

impl Default for File {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jcat::blob::Blob;
    use crate::jcat::types::BlobKind;

    #[test]
    fn file_json_roundtrip() {
        let mut file = File::new();
        let mut item = Item::new("firmware.bin");
        item.add_blobs([Blob::new_utf8(BlobKind::Sha256, "abc123")]);
        file.add_items([item]);

        let json = file.export_json().unwrap();
        let file2 = File::new_from_json(&json).unwrap();

        assert_eq!(file2.items().len(), 1);
        assert_eq!(file2.items()[0].id(), "firmware.bin");
        assert_eq!(file2.items()[0].blobs().len(), 1);
    }

    #[test]
    fn file_gzip_roundtrip() {
        let mut file = File::new();
        let item = Item::new("test.bin");
        file.add_items([item]);

        let compressed = file.export_bytes().unwrap();
        let file2 = File::new_from_bytes(&compressed).unwrap();

        assert_eq!(file2.items().len(), 1);
        assert_eq!(file2.items()[0].id(), "test.bin");
    }

    #[test]
    fn file_item_by_id() {
        let mut file = File::new();
        let mut item = Item::new("firmware.bin");
        item.add_alias_id("fw.bin");
        file.add_items([item]);

        assert!(file.item_by_id("firmware.bin").is_ok());
        assert!(file.item_by_id("fw.bin").is_ok());
        assert!(file.item_by_id("missing").is_err());
    }

    #[test]
    fn file_item_default() {
        let mut file = File::new();
        assert!(file.item_default().is_err()); // no items

        file.add_items([Item::new("a")]);
        assert!(file.item_default().is_ok()); // exactly one

        file.add_items([Item::new("b")]);
        assert!(file.item_default().is_err()); // too many
    }
}
