/*
 * Copyright 2026 Red Hat
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

//! JCat verification context.
//!
//! The context manages engines, public key directories, blob kind allowlists,
//! and orchestrates the two-phase verification logic (all checksums must pass,
//! at least one signature must pass).

use std::fs;
use std::path::{Path, PathBuf};

use super::blob::Blob;
use super::engine::EngineInstance;
use super::engine::pkcs7::Pkcs7Engine;
use super::engine::sha256::Sha256Engine;
use super::engine::sha512::Sha512Engine;
use super::error::Error;
use super::item::Item;
use super::result::VerifyResult;
use super::types::{BlobKind, BlobMethod, VerifyFlags};

/// Verification context holding engines, trust configuration and allowlists.
///
/// By default all blob kinds are denied. Call [`Context::allow_blob_kind()`] to
/// enable specific kinds before verification.
#[derive(Debug)]
pub struct Context {
    engines: Vec<EngineInstance>,
    public_keys: Vec<PathBuf>,
    keyring_path: PathBuf,
    blob_kinds: u32,
}

impl Context {
    /// Create a new context with default engines.
    ///
    /// SHA-256, SHA-512 and PKCS#7 engines are always registered.
    /// The keyring path defaults to `$XDG_DATA_HOME/fwupd`.
    pub fn new() -> Self {
        let keyring_path = dirs_keyring_path();

        let mut ctx = Self {
            engines: Vec::new(),
            public_keys: Vec::new(),
            keyring_path: keyring_path.clone(),
            blob_kinds: 0,
        };

        // Register built-in engines.
        ctx.engines.push(EngineInstance::new(
            Box::new(Sha256Engine::new()),
            keyring_path.clone(),
        ));
        ctx.engines.push(EngineInstance::new(
            Box::new(Sha512Engine::new()),
            keyring_path.clone(),
        ));
        ctx.engines.push(EngineInstance::new(
            Box::new(Pkcs7Engine::new(keyring_path.clone())),
            keyring_path,
        ));

        ctx
    }

    /// Add all files in `path` as public key files.
    ///
    /// Prefer [`ContextBuilder::public_keys()`] for new code; this method
    /// exists for FFI compatibility with the existing C API.
    pub fn add_public_keys(&mut self, path: &Path) {
        if let Ok(entries) = fs::read_dir(path) {
            for entry in entries.flatten() {
                self.public_keys.push(entry.path());
            }
        }
    }

    /// Returns all registered public key paths.
    pub fn public_keys(&self) -> &[PathBuf] {
        &self.public_keys
    }

    /// Set the keyring path (local state directory for engines).
    ///
    /// Prefer [`ContextBuilder::keyring_path()`] for new code; this method
    /// exists for FFI compatibility with the existing C API.
    pub fn set_keyring_path(&mut self, path: &Path) {
        self.keyring_path = path.to_path_buf();
        for engine in &mut self.engines {
            engine.set_keyring_path(path.to_path_buf());
        }
    }

    /// Returns the keyring path.
    pub fn keyring_path(&self) -> &Path {
        &self.keyring_path
    }

    /// Allow one or more blob kinds for verification.
    ///
    /// Prefer [`ContextBuilder::allow_blob_kind()`] for new code; this method
    /// exists for FFI compatibility with the existing C API.
    pub fn allow_blob_kind(&mut self, kinds: &[BlobKind]) {
        for kind in kinds {
            let k = u32::from(*kind);
            if k < BlobKind::COUNT {
                self.blob_kinds |= 1u32 << k;
            }
        }
    }

    /// Find the engine for a specific blob kind, checking the allowlist.
    ///
    /// Returns a mutable reference to the engine, or an error if the kind is
    /// not allowed or no engine supports it.
    fn engine_for(&mut self, kind: BlobKind) -> Result<&mut EngineInstance, Error> {
        let k = u32::from(kind);
        if k >= BlobKind::COUNT || (self.blob_kinds & (1u32 << k)) == 0 {
            return Err(Error::NotAllowed(format!(
                "JCat engine kind '{kind}' not allowed"
            )));
        }
        self.engines
            .iter_mut()
            .find(|e| e.kind() == kind)
            .ok_or_else(|| Error::NotFound(format!("JCat engine kind '{kind}' not supported")))
    }

    /// Verify a single blob against data.
    pub fn verify_blob(
        &mut self,
        data: &[u8],
        blob: &Blob,
        flags: VerifyFlags,
    ) -> Result<VerifyResult, Error> {
        let blob_data = blob.data();
        if blob_data.is_empty() {
            return Err(Error::InvalidData("blob has no signature data".into()));
        }
        let public_keys = self.public_keys.clone();
        let engine = self.engine_for(blob.kind())?;
        match engine.method() {
            BlobMethod::Checksum => engine.self_verify(data, blob_data, flags, &public_keys),
            BlobMethod::Signature => engine.pubkey_verify(data, blob_data, flags, &public_keys),
        }
    }

    /// Verify an item against data.
    ///
    /// All `CHECKSUM` blobs must verify. At least one `SIGNATURE` blob must
    /// verify (the rest may fail).
    pub fn verify_item(
        &mut self,
        data: &[u8],
        item: &Item,
        flags: VerifyFlags,
    ) -> Result<Vec<VerifyResult>, Error> {
        let blobs = item.blobs();
        if blobs.is_empty() {
            return Err(Error::NotSupported("no blobs in item".into()));
        }

        let mut results = Vec::new();

        let public_keys = self.public_keys.clone();

        // Phase 1: All checksum engines must verify.
        for blob in blobs {
            let engine = match self.engine_for(blob.kind()) {
                Ok(e) => e,
                Err(_) => continue, // Engine not available, skip.
            };

            if engine.method() != BlobMethod::Checksum {
                continue;
            }

            let result = engine.self_verify(data, blob.data(), flags, &public_keys)?;
            results.push(result);
        }

        if flags.contains(VerifyFlags::REQUIRE_CHECKSUM) && results.is_empty() {
            return Err(Error::NotFound(
                "checksums were required, but none supplied".into(),
            ));
        }

        // Phase 2: At least one signature must verify.
        let mut nr_signature = 0u32;
        for blob in blobs {
            let engine = match self.engine_for(blob.kind()) {
                Ok(e) => e,
                Err(_) => continue,
            };

            if engine.method() != BlobMethod::Signature {
                continue;
            }

            match engine.pubkey_verify(data, blob.data(), flags, &public_keys) {
                Ok(result) => {
                    results.push(result);
                    nr_signature += 1;
                }
                Err(_) => continue, // Signature failure is not fatal.
            }
        }

        if flags.contains(VerifyFlags::REQUIRE_SIGNATURE) && nr_signature == 0 {
            return Err(Error::NotFound(
                "signatures were required, but none verified".into(),
            ));
        }

        if results.is_empty() {
            return Err(Error::NotFound(
                "no valid checksums or signatures found".into(),
            ));
        }

        Ok(results)
    }

    /// Verify a target item against an item containing signatures.
    ///
    /// This is for the case where signatures cover checksums rather than raw
    /// data. The `item_target` contains the expected checksums computed from
    /// the original data. The `item` contains both checksums (which are
    /// compared against the target) and signatures (which sign the target
    /// checksums).
    pub fn verify_target(
        &mut self,
        item_target: &Item,
        item: &Item,
        flags: VerifyFlags,
    ) -> Result<Vec<VerifyResult>, Error> {
        let blobs = item.blobs();
        if blobs.is_empty() {
            return Err(Error::NotSupported("no blobs in item".into()));
        }

        let public_keys = self.public_keys.clone();
        let mut results = Vec::new();

        // Phase 1: All checksum blobs in item must match the target.
        for blob in blobs {
            let (engine_kind, engine_method) = match self.engine_for(blob.kind()) {
                Ok(e) => (e.kind(), e.method()),
                Err(_) => continue,
            };

            if engine_method != BlobMethod::Checksum {
                continue;
            }

            let target_blobs: Vec<_> = item_target
                .blobs()
                .iter()
                .filter(|b| b.kind() == blob.kind())
                .collect();
            let target_blob = match target_blobs.as_slice() {
                [one] => *one,
                _ => continue,
            };

            let checksum = blob.data_as_string().to_string();
            let checksum_target = target_blob.data_as_string().to_string();

            if checksum != checksum_target {
                return Err(Error::InvalidData(format!(
                    "{} checksum was {checksum} but target is {checksum_target}",
                    blob.kind()
                )));
            }

            results.push(VerifyResult::new(engine_kind, engine_method));
        }

        if flags.contains(VerifyFlags::REQUIRE_CHECKSUM) && results.is_empty() {
            return Err(Error::NotFound(
                "checksums were required, but none supplied".into(),
            ));
        }

        // Phase 2: At least one signature must verify against target data.
        let mut nr_signature = 0u32;
        for blob in blobs {
            let engine_method = match self.engine_for(blob.kind()) {
                Ok(e) => e.method(),
                Err(_) => continue,
            };

            if engine_method != BlobMethod::Signature {
                continue;
            }

            let blob_target = match blob.target() {
                Some(t) => t,
                None => continue,
            };

            let target_blobs: Vec<_> = item_target
                .blobs()
                .iter()
                .filter(|b| b.kind() == blob_target)
                .collect();
            let target_blob = match target_blobs.as_slice() {
                [one] => *one,
                _ => continue,
            };

            let engine = self.engine_for(blob.kind())?;
            match engine.pubkey_verify(target_blob.data(), blob.data(), flags, &public_keys) {
                Ok(result) => {
                    results.push(result);
                    nr_signature += 1;
                }
                Err(_) => continue,
            }
        }

        if flags.contains(VerifyFlags::REQUIRE_SIGNATURE) && nr_signature == 0 {
            return Err(Error::NotFound(
                "signatures were required, but none verified".into(),
            ));
        }

        if results.is_empty() {
            return Err(Error::NotFound(
                "no valid checksums or signatures found".into(),
            ));
        }

        Ok(results)
    }

    /// Get a mutable reference to the engine for a blob kind, for direct use.
    ///
    /// The engine is set up (public keys loaded) on first access.
    #[allow(dead_code)]
    pub(crate) fn engine_mut(&mut self, kind: BlobKind) -> Result<&mut EngineInstance, Error> {
        self.engine_for(kind)
    }
}

impl Default for Context {
    fn default() -> Self {
        Self::new()
    }
}

/// Builder for constructing a [`Context`] with configuration.
///
/// # Example
///
/// ```no_run
/// use fwupd::jcat::{ContextBuilder, BlobKind};
/// use std::path::Path;
///
/// let ctx = ContextBuilder::new()
///     .allow_blob_kind(&[BlobKind::Sha256, BlobKind::Pkcs7])
///     .public_keys(Path::new("/etc/pki/fwupd"))
///     .keyring_path(Path::new("/var/lib/fwupd"))
///     .build();
/// ```
pub struct ContextBuilder {
    blob_kinds: Vec<BlobKind>,
    public_key_dirs: Vec<PathBuf>,
    keyring_path: Option<PathBuf>,
}

impl ContextBuilder {
    /// Create a new builder with no configuration.
    pub fn new() -> Self {
        Self {
            blob_kinds: Vec::new(),
            public_key_dirs: Vec::new(),
            keyring_path: None,
        }
    }

    /// Allow one or more blob kinds for verification.
    pub fn allow_blob_kind(mut self, kinds: &[BlobKind]) -> Self {
        self.blob_kinds.extend_from_slice(kinds);
        self
    }

    /// Add a directory of public key files.
    pub fn public_keys(mut self, path: &Path) -> Self {
        self.public_key_dirs.push(path.to_path_buf());
        self
    }

    /// Set the keyring path (local state directory for engines).
    pub fn keyring_path(mut self, path: &Path) -> Self {
        self.keyring_path = Some(path.to_path_buf());
        self
    }

    /// Build the [`Context`].
    pub fn build(self) -> Context {
        let mut ctx = Context::new();
        if let Some(path) = self.keyring_path {
            ctx.set_keyring_path(&path);
        }
        for dir in &self.public_key_dirs {
            ctx.add_public_keys(dir);
        }
        ctx.allow_blob_kind(&self.blob_kinds);
        ctx
    }
}

impl Default for ContextBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Compute the default keyring path: `$XDG_DATA_HOME/fwupd`.
fn dirs_keyring_path() -> PathBuf {
    if let Some(data_dir) = std::env::var_os("XDG_DATA_HOME") {
        PathBuf::from(data_dir).join("fwupd")
    } else if let Some(home) = std::env::var_os("HOME") {
        PathBuf::from(home).join(".local/share/fwupd")
    } else {
        PathBuf::from("/tmp/fwupd")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jcat::blob::Blob;
    use crate::jcat::types::BlobFlags;

    /// Path to the test fixture directory (src/tests/ relative to the repo root).
    fn test_dir() -> PathBuf {
        let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        // rust/fwupd/Cargo.toml -> repo root is ../../
        manifest.join("../../src/tests")
    }

    fn firmware_bin() -> Vec<u8> {
        std::fs::read(test_dir().join("colorhug/firmware.bin")).unwrap()
    }

    fn firmware_sig_p7b() -> Vec<u8> {
        std::fs::read(test_dir().join("colorhug/firmware.bin.p7b")).unwrap()
    }

    fn firmware_sig_p7c() -> Vec<u8> {
        std::fs::read(test_dir().join("colorhug/firmware.bin.p7c")).unwrap()
    }

    // -- SHA-256 engine (matches fu_jcat_sha256_engine_func) --

    #[test]
    fn sha256_verify_known_checksum() {
        let data = firmware_bin();
        let expected = "a948904f2f0f479b8f8197694b30184b0d2ed1c1cd2a1ec0fb85d299a192a447";

        let mut ctx = Context::new();
        ctx.allow_blob_kind(&[BlobKind::Sha256]);

        let blob = Blob::new_utf8(BlobKind::Sha256, expected);
        let result = ctx.verify_blob(&data, &blob, VerifyFlags::NONE).unwrap();
        assert_eq!(result.kind(), BlobKind::Sha256);
        assert_eq!(result.method(), BlobMethod::Checksum);
        assert_eq!(result.timestamp(), 0);
        assert_eq!(result.authority(), None);
    }

    #[test]
    fn sha256_verify_wrong_data_fails() {
        let wrong_data = std::fs::read(test_dir().join("colorhug/firmware.bin.asc")).unwrap();
        let expected = "a948904f2f0f479b8f8197694b30184b0d2ed1c1cd2a1ec0fb85d299a192a447";

        let mut ctx = Context::new();
        ctx.allow_blob_kind(&[BlobKind::Sha256]);

        let blob = Blob::new_utf8(BlobKind::Sha256, expected);
        let result = ctx.verify_blob(&wrong_data, &blob, VerifyFlags::NONE);
        assert!(result.is_err());
    }

    // -- SHA-512 engine (matches fu_jcat_sha512_engine_func) --

    #[test]
    fn sha512_verify_known_checksum() {
        let data = firmware_bin();
        let expected = "db3974a97f2407b7cae1ae637c0030687a11913274d578492558e39c16c017de84eacdc8c62fe34ee4e12b4b1428817f09b6a2760c3f8a664ceae94d2434a593";

        let mut ctx = Context::new();
        ctx.allow_blob_kind(&[BlobKind::Sha512]);

        let blob = Blob::new_utf8(BlobKind::Sha512, expected);
        let result = ctx.verify_blob(&data, &blob, VerifyFlags::NONE).unwrap();
        assert_eq!(result.kind(), BlobKind::Sha512);
        assert_eq!(result.method(), BlobMethod::Checksum);
    }

    // -- PKCS7 engine with CA certs (matches fwupd_jcat_pkcs7_engine_func) --

    #[test]
    fn pkcs7_pubkey_verify_lvfs_signature() {
        let data = firmware_bin();
        let sig = firmware_sig_p7b();

        let mut ctx = Context::new();
        ctx.allow_blob_kind(&[BlobKind::Pkcs7]);
        ctx.add_public_keys(&test_dir().join("pki"));

        let blob = Blob::new(BlobKind::Pkcs7, sig, BlobFlags::NONE);
        let result = ctx
            .verify_blob(&data, &blob, VerifyFlags::DISABLE_TIME_CHECKS)
            .unwrap();
        assert_eq!(result.kind(), BlobKind::Pkcs7);
        assert_eq!(result.method(), BlobMethod::Signature);
        assert!(result.timestamp() >= 1502871248);
        assert_eq!(
            result.authority().unwrap(),
            "O=Linux Vendor Firmware Project,CN=LVFS CA"
        );
    }

    #[test]
    fn pkcs7_pubkey_verify_self_signed_fixture() {
        let data = firmware_bin();
        let sig = firmware_sig_p7c();

        let mut ctx = Context::new();
        ctx.allow_blob_kind(&[BlobKind::Pkcs7]);
        ctx.add_public_keys(&test_dir().join("pki"));

        let blob = Blob::new(BlobKind::Pkcs7, sig, BlobFlags::NONE);
        let result = ctx.verify_blob(&data, &blob, VerifyFlags::NONE).unwrap();
        assert_eq!(result.kind(), BlobKind::Pkcs7);
        assert_eq!(result.authority().unwrap(), "O=Hughski Limited");
    }

    #[test]
    fn pkcs7_pubkey_verify_wrong_data_fails() {
        let wrong_data = std::fs::read(test_dir().join("colorhug/firmware.bin.asc")).unwrap();
        let sig = firmware_sig_p7b();

        let mut ctx = Context::new();
        ctx.allow_blob_kind(&[BlobKind::Pkcs7]);
        ctx.add_public_keys(&test_dir().join("pki"));

        let blob = Blob::new(BlobKind::Pkcs7, sig, BlobFlags::NONE);
        let result = ctx.verify_blob(&wrong_data, &blob, VerifyFlags::NONE);
        assert!(result.is_err());
    }

    // -- Context verify_blob disallow (matches fu_jcat_context_verify_blob_disallow_func) --

    #[test]
    fn verify_blob_disallowed_kind() {
        let data = firmware_bin();
        let sig = firmware_sig_p7b();

        // Context with NO blob kinds allowed.
        let mut ctx = Context::new();
        ctx.add_public_keys(&test_dir().join("pki"));

        let blob = Blob::new(BlobKind::Pkcs7, sig, BlobFlags::NONE);
        let result = ctx.verify_blob(&data, &blob, VerifyFlags::DISABLE_TIME_CHECKS);
        assert!(result.is_err());
    }

    // -- Context verify_blob for GPG (not allowed) --

    #[test]
    fn verify_blob_gpg_not_supported() {
        let mut ctx = Context::new();
        ctx.allow_blob_kind(&[BlobKind::Pkcs7, BlobKind::Sha256]);

        let engine_result = ctx.engine_for(BlobKind::Gpg);
        assert!(engine_result.is_err());
    }

    // -- Context verify_item with signature (matches fu_jcat_context_verify_item_sign_func) --

    #[test]
    fn verify_item_with_signature() {
        let data = firmware_bin();
        let sig = firmware_sig_p7b();

        let mut ctx = Context::new();
        ctx.allow_blob_kind(&[BlobKind::Pkcs7, BlobKind::Sha256]);
        ctx.add_public_keys(&test_dir().join("pki"));

        let mut item = Item::new("filename.bin");
        item.add_blobs([Blob::new(BlobKind::Pkcs7, sig, BlobFlags::NONE)]);

        let results = ctx
            .verify_item(
                &data,
                &item,
                VerifyFlags::DISABLE_TIME_CHECKS | VerifyFlags::REQUIRE_SIGNATURE,
            )
            .unwrap();
        assert_eq!(results.len(), 1);
        assert!(results[0].timestamp() >= 1502871248);
        assert_eq!(
            results[0].authority().unwrap(),
            "O=Linux Vendor Firmware Project,CN=LVFS CA"
        );
    }

    #[test]
    fn verify_item_require_checksum_fails_when_none() {
        let data = firmware_bin();
        let sig = firmware_sig_p7b();

        let mut ctx = Context::new();
        ctx.allow_blob_kind(&[BlobKind::Pkcs7, BlobKind::Sha256]);
        ctx.add_public_keys(&test_dir().join("pki"));

        let mut item = Item::new("filename.bin");
        item.add_blobs([Blob::new(BlobKind::Pkcs7, sig, BlobFlags::NONE)]);

        // Require checksum but none provided — should fail.
        let result = ctx.verify_item(
            &data,
            &item,
            VerifyFlags::DISABLE_TIME_CHECKS | VerifyFlags::REQUIRE_CHECKSUM,
        );
        assert!(result.is_err());
    }

    // -- Context verify_item with checksum (matches fu_jcat_context_verify_item_csum_func) --

    #[test]
    fn verify_item_with_checksum() {
        let data = firmware_bin();
        let checksum = "a948904f2f0f479b8f8197694b30184b0d2ed1c1cd2a1ec0fb85d299a192a447";

        let mut ctx = Context::new();
        ctx.allow_blob_kind(&[BlobKind::Pkcs7, BlobKind::Sha256]);
        ctx.add_public_keys(&test_dir().join("pki"));

        let mut item = Item::new("filename.bin");
        item.add_blobs([Blob::new_utf8(BlobKind::Sha256, checksum)]);

        let results = ctx
            .verify_item(
                &data,
                &item,
                VerifyFlags::DISABLE_TIME_CHECKS | VerifyFlags::REQUIRE_CHECKSUM,
            )
            .unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].timestamp(), 0);
        assert_eq!(results[0].authority(), None);
    }

    #[test]
    fn verify_item_require_signature_fails_when_none() {
        let data = firmware_bin();
        let checksum = "a948904f2f0f479b8f8197694b30184b0d2ed1c1cd2a1ec0fb85d299a192a447";

        let mut ctx = Context::new();
        ctx.allow_blob_kind(&[BlobKind::Pkcs7, BlobKind::Sha256]);
        ctx.add_public_keys(&test_dir().join("pki"));

        let mut item = Item::new("filename.bin");
        item.add_blobs([Blob::new_utf8(BlobKind::Sha256, checksum)]);

        let result = ctx.verify_item(
            &data,
            &item,
            VerifyFlags::DISABLE_TIME_CHECKS | VerifyFlags::REQUIRE_SIGNATURE,
        );
        assert!(result.is_err());
    }
}
