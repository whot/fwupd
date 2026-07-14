/*
 * Copyright 2026 Red Hat
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

//! Verification and signing engines.
//!
//! Each engine handles a specific [`BlobKind`] and provides either checksum
//! self-verification or public-key signature verification.

pub(crate) mod pkcs7;
pub(crate) mod sha256;
pub(crate) mod sha512;

use std::fmt;
use std::path::{Path, PathBuf};

use super::blob::Blob;
use super::error::Error;
use super::result::VerifyResult;
use super::types::{BlobKind, BlobMethod, SignFlags, VerifyFlags};

// Re-exported for use by context.rs and external consumers.
#[allow(unused_imports)]
pub use pkcs7::Pkcs7Engine;
#[allow(unused_imports)]
pub use sha256::Sha256Engine;
#[allow(unused_imports)]
pub use sha512::Sha512Engine;

/// Trait implemented by all verification/signing engines.
pub trait Engine: fmt::Debug + Send + Sync {
    /// Returns the blob kind this engine handles.
    fn kind(&self) -> BlobKind;

    /// Returns the verification method (checksum vs signature).
    fn method(&self) -> BlobMethod;

    /// Set up the engine (called lazily before first use).
    ///
    /// The default implementation is a no-op.
    fn setup(&mut self, _public_key_paths: &[PathBuf]) -> Result<(), Error> {
        Ok(())
    }

    /// Verify data against a checksum/self-generated signature.
    ///
    /// Returns `Err(NotSupported)` if not applicable to this engine.
    fn self_verify(
        &self,
        data: &[u8],
        signature: &[u8],
        flags: VerifyFlags,
    ) -> Result<VerifyResult, Error>;

    /// Sign data, producing a blob containing the checksum or self-signed signature.
    ///
    /// Returns `Err(NotSupported)` if not applicable to this engine.
    fn self_sign(&self, data: &[u8], flags: SignFlags) -> Result<Blob, Error>;

    /// Verify data against a detached public-key signature.
    ///
    /// Returns `Err(NotSupported)` if not applicable to this engine.
    fn pubkey_verify(
        &self,
        data: &[u8],
        signature: &[u8],
        flags: VerifyFlags,
    ) -> Result<VerifyResult, Error> {
        let _ = (data, signature, flags);
        Err(Error::NotSupported(
            "verifying data is not supported".into(),
        ))
    }

    /// Sign data with a public key pair, producing a detached signature blob.
    ///
    /// Returns `Err(NotSupported)` if not applicable to this engine.
    fn pubkey_sign(
        &self,
        data: &[u8],
        cert: &[u8],
        privkey: &[u8],
        flags: SignFlags,
    ) -> Result<Blob, Error> {
        let _ = (data, cert, privkey, flags);
        Err(Error::NotSupported("signing data is not supported".into()))
    }

    /// Add a raw public key (as bytes) to the engine's trust store.
    ///
    /// Returns `Err(NotSupported)` if not applicable to this engine.
    fn add_public_key_raw(&mut self, _blob: &[u8]) -> Result<(), Error> {
        Err(Error::NotSupported(
            "adding public keys manually is not supported".into(),
        ))
    }

    /// Update the keyring path. Default implementation is a no-op.
    fn set_keyring_path(&mut self, _path: &std::path::Path) {}
}

/// An engine wrapper that handles lazy setup and keyring path management.
#[allow(dead_code)]
pub(crate) struct EngineInstance {
    inner: Box<dyn Engine>,
    done_setup: bool,
    keyring_path: PathBuf,
}

impl fmt::Debug for EngineInstance {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EngineInstance")
            .field("kind", &self.inner.kind())
            .field("method", &self.inner.method())
            .field("done_setup", &self.done_setup)
            .finish()
    }
}

#[allow(dead_code)]
impl EngineInstance {
    pub fn new(engine: Box<dyn Engine>, keyring_path: PathBuf) -> Self {
        Self {
            inner: engine,
            done_setup: false,
            keyring_path,
        }
    }

    pub fn kind(&self) -> BlobKind {
        self.inner.kind()
    }

    pub fn method(&self) -> BlobMethod {
        self.inner.method()
    }

    pub fn keyring_path(&self) -> &Path {
        &self.keyring_path
    }

    pub fn set_keyring_path(&mut self, path: PathBuf) {
        self.keyring_path = path.clone();
        // Propagate to the inner engine (e.g., Pkcs7Engine needs it).
        self.inner.set_keyring_path(&path);
        // Reset setup state so public keys are reloaded from the new path.
        self.done_setup = false;
    }

    /// Ensure the engine is set up, loading public keys if needed.
    fn ensure_setup(&mut self, public_keys: &[PathBuf]) -> Result<(), Error> {
        if self.done_setup {
            return Ok(());
        }
        self.inner.setup(public_keys)?;
        self.done_setup = true;
        Ok(())
    }

    pub fn self_verify(
        &mut self,
        data: &[u8],
        signature: &[u8],
        flags: VerifyFlags,
        public_keys: &[PathBuf],
    ) -> Result<VerifyResult, Error> {
        self.ensure_setup(public_keys)?;
        self.inner.self_verify(data, signature, flags)
    }

    pub fn self_sign(
        &mut self,
        data: &[u8],
        flags: SignFlags,
        public_keys: &[PathBuf],
    ) -> Result<Blob, Error> {
        self.ensure_setup(public_keys)?;
        self.inner.self_sign(data, flags)
    }

    pub fn pubkey_verify(
        &mut self,
        data: &[u8],
        signature: &[u8],
        flags: VerifyFlags,
        public_keys: &[PathBuf],
    ) -> Result<VerifyResult, Error> {
        self.ensure_setup(public_keys)?;
        self.inner.pubkey_verify(data, signature, flags)
    }

    pub fn pubkey_sign(
        &mut self,
        data: &[u8],
        cert: &[u8],
        privkey: &[u8],
        flags: SignFlags,
        public_keys: &[PathBuf],
    ) -> Result<Blob, Error> {
        self.ensure_setup(public_keys)?;
        self.inner.pubkey_sign(data, cert, privkey, flags)
    }

    pub fn add_public_key_raw(&mut self, blob: &[u8]) -> Result<(), Error> {
        self.inner.add_public_key_raw(blob)
    }
}
