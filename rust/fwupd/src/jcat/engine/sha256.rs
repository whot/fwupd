/*
 * Copyright 2026 Red Hat
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

//! SHA-256 checksum engine.

use sha2::{Digest, Sha256};

use crate::jcat::blob::Blob;
use crate::jcat::error::Error;
use crate::jcat::result::VerifyResult;
use crate::jcat::types::{BlobKind, BlobMethod, SignFlags, VerifyFlags};

use super::Engine;

/// Engine for SHA-256 checksum verification and generation.
#[derive(Debug)]
pub struct Sha256Engine;

impl Sha256Engine {
    pub fn new() -> Self {
        Self
    }

    fn compute_hex(data: &[u8]) -> String {
        let hash = Sha256::digest(data);
        hex::encode(hash)
    }
}

impl Engine for Sha256Engine {
    fn kind(&self) -> BlobKind {
        BlobKind::Sha256
    }

    fn method(&self) -> BlobMethod {
        BlobMethod::Checksum
    }

    fn self_verify(
        &self,
        data: &[u8],
        signature: &[u8],
        _flags: VerifyFlags,
    ) -> Result<VerifyResult, Error> {
        let computed = Self::compute_hex(data);
        let expected = std::str::from_utf8(signature)
            .map_err(|_| Error::InvalidData("checksum signature is not valid UTF-8".into()))?;
        if computed != expected {
            return Err(Error::InvalidData(format!(
                "expected {expected} and got {computed}: SHA-256 checksum mismatch"
            )));
        }
        Ok(VerifyResult::new_checksum(BlobKind::Sha256))
    }

    fn self_sign(&self, data: &[u8], _flags: SignFlags) -> Result<Blob, Error> {
        let hex = Self::compute_hex(data);
        Ok(Blob::new_utf8(BlobKind::Sha256, &hex))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_sign_and_verify() {
        let engine = Sha256Engine::new();
        let data = b"hello world";
        let blob = engine.self_sign(data, SignFlags::NONE).unwrap();
        let result = engine
            .self_verify(data, blob.data(), VerifyFlags::NONE)
            .unwrap();
        assert_eq!(result.kind(), BlobKind::Sha256);
        assert_eq!(result.method(), BlobMethod::Checksum);
        assert_eq!(result.timestamp(), 0);
        assert_eq!(result.authority(), None);
    }

    #[test]
    fn sha256_verify_mismatch() {
        let engine = Sha256Engine::new();
        let result = engine.self_verify(
            b"hello",
            b"0000000000000000000000000000000000000000000000000000000000000000",
            VerifyFlags::NONE,
        );
        assert!(result.is_err());
    }
}
