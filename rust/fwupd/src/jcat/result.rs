/*
 * Copyright 2026 Red Hat
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

//! Verification result returned by engine operations.

use super::types::{BlobKind, BlobMethod};

/// The result of a successful verification operation.
///
/// Contains metadata about the verification: what kind of engine verified it,
/// the verification method, an optional signing authority, and an optional
/// signing timestamp.
///
/// # Example
///
/// ```
/// use fwupd::jcat::{VerifyResult, BlobKind, BlobMethod};
///
/// let result = VerifyResult::new_checksum(BlobKind::Sha256);
/// assert_eq!(result.kind(), BlobKind::Sha256);
/// assert_eq!(result.method(), BlobMethod::Checksum);
/// assert_eq!(result.timestamp(), 0);
/// assert_eq!(result.authority(), None);
/// ```
#[derive(Debug, Clone)]
pub struct VerifyResult {
    kind: BlobKind,
    method: BlobMethod,
    timestamp: i64,
    authority: Option<String>,
}

impl VerifyResult {
    /// Create a new result for a checksum verification (no authority or timestamp).
    pub fn new_checksum(kind: BlobKind) -> Self {
        Self {
            kind,
            method: BlobMethod::Checksum,
            timestamp: 0,
            authority: None,
        }
    }

    /// Create a new result for a signature verification.
    pub fn new_signature(kind: BlobKind, timestamp: i64, authority: Option<String>) -> Self {
        Self {
            kind,
            method: BlobMethod::Signature,
            timestamp,
            authority,
        }
    }

    /// Create a new result with explicit kind and method.
    pub fn new(kind: BlobKind, method: BlobMethod) -> Self {
        Self {
            kind,
            method,
            timestamp: 0,
            authority: None,
        }
    }

    /// Returns the signing timestamp (UNIX seconds), or 0 if unset.
    pub fn timestamp(&self) -> i64 {
        self.timestamp
    }

    /// Sets the signing timestamp.
    #[allow(dead_code)]
    pub(crate) fn set_timestamp(&mut self, ts: i64) {
        self.timestamp = ts;
    }

    /// Returns the signing authority string, if set.
    pub fn authority(&self) -> Option<&str> {
        self.authority.as_deref()
    }

    /// Returns the blob kind that produced this result.
    pub fn kind(&self) -> BlobKind {
        self.kind
    }

    /// Returns the verification method.
    pub fn method(&self) -> BlobMethod {
        self.method
    }
}
