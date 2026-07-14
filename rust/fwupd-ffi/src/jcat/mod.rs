/*
 * Copyright 2026 Red Hat
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

//! C-compatible FFI wrappers for the JCat module.
//!
//! These functions provide the same API as the C `fu_jcat_context_*`,
//! `fu_jcat_engine_*`, and `fu_jcat_result_*` functions, wrapping the
//! pure-Rust implementations from [`fwupd::jcat`].
//!
//! The GObject data types (`FwupdJcatBlob`, `FwupdJcatItem`, `FwupdJcatFile`)
//! remain C-implemented in libfwupd. This module provides the processing
//! functions (`fu_jcat_context_*` etc.) that operate on those types.

mod context;
mod engine;
mod result;

pub use context::*;

use fwupd::jcat;
use std::ffi::CString;

/// Opaque handle to a Rust JCat context, stored as a boxed pointer.
///
/// In the C API this replaces `FuJcatContext *`.  C callers create one via
/// `fu_jcat_context_new_rs()`, use it with the `fu_jcat_context_*_rs()`
/// functions, and free it with `fu_jcat_context_free_rs()`.
pub struct FuJcatContextRs {
    inner: jcat::Context,
    /// Cached CString for keyring_path so we can return a stable pointer.
    keyring_path_cstr: Option<CString>,
}

/// Opaque handle to a verification result.
pub struct FuJcatResultRs {
    inner: jcat::VerifyResult,
    /// Cached CString for authority so we can return a stable pointer.
    authority_cstr: Option<CString>,
}

impl FuJcatResultRs {
    fn new(result: jcat::VerifyResult) -> Self {
        let authority_cstr = result
            .authority()
            .and_then(|s| CString::new(s.replace('\0', "")).ok());
        Self {
            inner: result,
            authority_cstr,
        }
    }
}

/// Descriptor for a single blob, passed from C to the verify_item/verify_target
/// FFI functions.
#[repr(C)]
pub struct FuJcatBlobDescriptor {
    pub kind: u32,
    pub target: u32,
    pub data: *const u8,
    pub data_len: usize,
    pub is_utf8: bool,
}
