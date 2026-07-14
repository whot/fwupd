/*
 * Copyright 2026 Red Hat
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

//! JCat item — a named collection of blobs within a file.

use serde::{Deserialize, Serialize};
use std::path::Path;

use super::blob::Blob;
use super::error::Error;

/// An item within a [`File`](crate::jcat::File), identified by an ID (typically a filename).
///
/// Each item contains zero or more [`Blob`]s (checksums and/or signatures)
/// and optional alias IDs that can be used to look up the item.
///
/// # Example
///
/// ```
/// use fwupd::jcat::{Item, Blob, BlobKind};
///
/// let mut item = Item::new("firmware.bin");
/// item.add_blobs([Blob::new_utf8(BlobKind::Sha256, "abcdef...")]);
/// item.add_alias_id("fw.bin");
/// assert_eq!(item.blobs().len(), 1);
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Item {
    id: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    alias_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    blobs: Vec<Blob>,
}

impl Item {
    /// Create a new item with the given ID.
    pub fn new(id: &str) -> Self {
        Self {
            id: id.to_string(),
            alias_ids: Vec::new(),
            blobs: Vec::new(),
        }
    }

    /// Returns the item ID.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Returns the item ID if it is safe to use as a file path component
    /// (no directory separators, not `.` or `..`).
    pub fn id_safe(&self) -> Result<&str, Error> {
        if self.id.is_empty() {
            return Err(Error::InvalidData("ID not set".into()));
        }
        let basename = Path::new(&self.id)
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("");
        if basename != self.id || basename == "." || basename == ".." {
            return Err(Error::InvalidData(
                "ID cannot contain path components".into(),
            ));
        }
        Ok(&self.id)
    }

    /// Returns all blobs in this item.
    pub fn blobs(&self) -> &[Blob] {
        &self.blobs
    }

    /// Add one or more blobs to this item.
    pub fn add_blobs(&mut self, blobs: impl IntoIterator<Item = Blob>) {
        self.blobs.extend(blobs);
    }

    /// Add an alias ID.
    pub fn add_alias_id(&mut self, id: &str) {
        if !self.alias_ids.iter().any(|existing| existing == id) {
            self.alias_ids.push(id.to_string());
        }
    }

    /// Remove an alias ID.
    pub fn remove_alias_id(&mut self, id: &str) {
        self.alias_ids.retain(|existing| existing != id);
    }

    /// Returns the alias IDs.
    pub fn alias_ids(&self) -> &[String] {
        &self.alias_ids
    }

    /// Returns `true` if any blob has a target set (for target verification).
    pub fn has_target(&self) -> bool {
        self.blobs.iter().any(|b| b.target().is_some())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jcat::blob::Blob;
    use crate::jcat::types::{BlobFlags, BlobKind};

    #[test]
    fn item_id_safe() {
        let item = Item::new("firmware.bin");
        assert_eq!(item.id_safe().unwrap(), "firmware.bin");

        let bad = Item::new("../etc/passwd");
        assert!(bad.id_safe().is_err());

        let empty = Item::new("");
        assert!(empty.id_safe().is_err());
    }

    #[test]
    fn item_alias_ids() {
        let mut item = Item::new("test");
        item.add_alias_id("alias1");
        item.add_alias_id("alias2");
        item.add_alias_id("alias1"); // duplicate, should not be added
        assert_eq!(item.alias_ids().len(), 2);

        item.remove_alias_id("alias1");
        assert_eq!(item.alias_ids().len(), 1);
        assert_eq!(item.alias_ids()[0], "alias2");
    }

    #[test]
    fn item_filter_blobs_by_kind() {
        let mut item = Item::new("test");
        let blob = Blob::new_utf8(BlobKind::Sha256, "abc");
        item.add_blobs([blob]);
        assert_eq!(
            item.blobs()
                .iter()
                .filter(|b| b.kind() == BlobKind::Sha256)
                .count(),
            1
        );
        assert_eq!(
            item.blobs()
                .iter()
                .filter(|b| b.kind() == BlobKind::Sha512)
                .count(),
            0
        );
    }

    #[test]
    fn item_serialization_roundtrip() {
        let mut item = Item::new("firmware.bin");
        item.add_blobs([Blob::new_utf8(BlobKind::Sha256, "abc123")]);
        item.add_alias_id("fw.bin");

        let json = serde_json::to_string(&item).unwrap();
        let parsed: Item = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.id(), "firmware.bin");
        assert_eq!(parsed.blobs().len(), 1);
        assert_eq!(parsed.alias_ids(), &["fw.bin"]);
    }

    #[test]
    fn item_has_target() {
        let mut item = Item::new("test");
        assert!(!item.has_target());

        let mut blob = Blob::new_utf8(BlobKind::Pkcs7, "sig");
        blob.set_target(BlobKind::Sha256);
        item.add_blobs([blob]);
        assert!(item.has_target());
    }
}
