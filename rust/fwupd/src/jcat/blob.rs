/*
 * Copyright 2026 Red Hat
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

//! JCat blob — a single signature or checksum within an item.

use base64::Engine as _;
use serde::de::{self, Deserializer};
use serde::ser::Serializer;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

use super::types::{BlobFlags, BlobKind};

/// The string representation of blob data, distinguishing between
/// UTF-8 text and base64-encoded binary.
///
/// # Example
///
/// ```
/// use fwupd::jcat::{Blob, BlobData, BlobKind, BlobFlags};
///
/// let blob = Blob::new_utf8(BlobKind::Sha256, "abcdef");
/// match blob.data_as_string() {
///     BlobData::Utf8(s) => assert_eq!(s, "abcdef"),
///     BlobData::Base64(_) => panic!("expected UTF-8"),
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlobData {
    /// The data is valid UTF-8 text (e.g. a hex checksum string or PEM).
    Utf8(String),
    /// The data is base64-encoded binary.
    Base64(String),
}

impl std::fmt::Display for BlobData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BlobData::Utf8(s) | BlobData::Base64(s) => f.write_str(s),
        }
    }
}

/// A single blob of signature or checksum data within an [`Item`](crate::jcat::Item).
///
/// Blobs carry the raw signature/checksum bytes, the algorithm kind, optional
/// flags, an optional target kind (for target verification), and a creation
/// timestamp.
///
/// # Example
///
/// ```
/// use fwupd::jcat::{Blob, BlobKind, BlobFlags};
///
/// // Create a UTF-8 checksum blob
/// let blob = Blob::new_utf8(BlobKind::Sha256, "deadbeef...");
/// assert_eq!(blob.kind(), BlobKind::Sha256);
///
/// // Create a binary blob
/// let sig = Blob::new(BlobKind::Pkcs7, vec![0x30, 0x82], BlobFlags::NONE);
/// assert_eq!(sig.kind(), BlobKind::Pkcs7);
/// ```
#[derive(Debug, Clone)]
pub struct Blob {
    kind: BlobKind,
    target: Option<BlobKind>,
    flags: BlobFlags,
    data: Vec<u8>,
    timestamp: u64,
}

impl Blob {
    /// Create a new blob with the given kind, raw data and flags.
    pub fn new(kind: BlobKind, data: Vec<u8>, flags: BlobFlags) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        Self {
            kind,
            target: None,
            flags,
            data,
            timestamp,
        }
    }

    /// Create a new blob containing UTF-8 text data.
    ///
    /// The `IS_UTF8` flag is set automatically.
    pub fn new_utf8(kind: BlobKind, text: &str) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        Self {
            kind,
            target: None,
            flags: BlobFlags::IS_UTF8,
            data: text.as_bytes().to_vec(),
            timestamp,
        }
    }

    /// Returns the blob kind.
    pub fn kind(&self) -> BlobKind {
        self.kind
    }

    /// Returns the blob target kind (for target verification).
    pub fn target(&self) -> Option<BlobKind> {
        self.target
    }

    /// Sets the blob target kind.
    pub fn set_target(&mut self, target: BlobKind) {
        self.target = Some(target);
    }

    /// Returns the blob flags.
    pub fn flags(&self) -> BlobFlags {
        self.flags
    }

    /// Returns the raw data bytes.
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Returns the data as a string representation.
    ///
    /// If the blob has the `IS_UTF8` flag, returns [`BlobData::Utf8`].
    /// Otherwise returns [`BlobData::Base64`] with base64-encoded binary.
    pub fn data_as_string(&self) -> BlobData {
        if self.flags.contains(BlobFlags::IS_UTF8) {
            BlobData::Utf8(String::from_utf8_lossy(&self.data).into_owned())
        } else {
            BlobData::Base64(base64::engine::general_purpose::STANDARD.encode(&self.data))
        }
    }

    /// Returns the creation timestamp (UNIX seconds).
    pub fn timestamp(&self) -> u64 {
        self.timestamp
    }

    /// Sets the creation timestamp.
    #[allow(dead_code)]
    pub(crate) fn set_timestamp(&mut self, timestamp: u64) {
        self.timestamp = timestamp;
    }
}

// -- Serde support ----------------------------------------------------------
// The JSON representation matches the C FwupdJcatBlob codec exactly:
//   { "Kind": <int>, "Flags": <int>, "Timestamp": <int>, "Target": <int>, "Data": "<string>" }

impl Serialize for Blob {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        let mut len = 3; // Kind + Flags + Data always present
        if self.timestamp > 0 {
            len += 1;
        }
        if self.target.is_some() {
            len += 1;
        }
        let mut map = serializer.serialize_map(Some(len))?;
        map.serialize_entry("Kind", &u32::from(self.kind))?;
        if let Some(target) = self.target {
            map.serialize_entry("Target", &u32::from(target))?;
        }
        map.serialize_entry("Flags", &self.flags.bits())?;
        if self.timestamp > 0 {
            map.serialize_entry("Timestamp", &self.timestamp)?;
        }
        map.serialize_entry("Data", &self.data_as_string().to_string())?;
        map.end()
    }
}

impl<'de> Deserialize<'de> for Blob {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(rename_all = "PascalCase")]
        struct BlobHelper {
            kind: u32,
            flags: u32,
            #[serde(default)]
            timestamp: u64,
            #[serde(default)]
            target: Option<u32>,
            data: String,
        }

        let h = BlobHelper::deserialize(deserializer)?;

        let kind = BlobKind::try_from(h.kind)
            .map_err(|v| de::Error::custom(format!("unknown blob kind {v}")))?;
        let flags = BlobFlags::from_bits_truncate(h.flags);
        let target = h.target.and_then(|v| BlobKind::try_from(v).ok());

        // Decode data: if IS_UTF8 the data is stored as plain text, otherwise base64.
        let data = if flags.contains(BlobFlags::IS_UTF8) {
            h.data.into_bytes()
        } else {
            base64::engine::general_purpose::STANDARD
                .decode(&h.data)
                .map_err(de::Error::custom)?
        };

        Ok(Blob {
            kind,
            target,
            flags,
            data,
            timestamp: h.timestamp,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utf8_blob_roundtrip() {
        let blob = Blob::new_utf8(BlobKind::Sha256, "abc123");
        assert_eq!(blob.kind(), BlobKind::Sha256);
        assert!(blob.flags().contains(BlobFlags::IS_UTF8));
        assert_eq!(blob.data_as_string(), BlobData::Utf8("abc123".into()));

        let json = serde_json::to_string(&blob).unwrap();
        let parsed: Blob = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.kind(), BlobKind::Sha256);
        assert_eq!(parsed.data_as_string(), BlobData::Utf8("abc123".into()));
    }

    #[test]
    fn binary_blob_roundtrip() {
        let data = vec![0xde, 0xad, 0xbe, 0xef];
        let blob = Blob::new(BlobKind::Pkcs7, data.clone(), BlobFlags::NONE);
        assert!(!blob.flags().contains(BlobFlags::IS_UTF8));

        let json = serde_json::to_string(&blob).unwrap();
        let parsed: Blob = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.data(), &data);
    }

    #[test]
    fn target_roundtrip() {
        let mut blob = Blob::new_utf8(BlobKind::Pkcs7, "sig");
        blob.set_target(BlobKind::Sha256);
        assert_eq!(blob.target(), Some(BlobKind::Sha256));

        let json = serde_json::to_string(&blob).unwrap();
        let parsed: Blob = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.target(), Some(BlobKind::Sha256));
    }

    #[test]
    fn no_target() {
        let blob = Blob::new_utf8(BlobKind::Sha256, "abc");
        assert_eq!(blob.target(), None);
    }
}
