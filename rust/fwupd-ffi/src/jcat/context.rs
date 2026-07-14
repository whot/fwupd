/*
 * Copyright 2026 Red Hat
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

//! FFI wrappers for FuJcatContext and FuJcatResult operations.

use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::path::PathBuf;

use fwupd::jcat;

use super::{FuJcatBlobDescriptor, FuJcatContextRs, FuJcatResultRs};

// ---------------------------------------------------------------------------
// Context lifecycle
// ---------------------------------------------------------------------------

/// Create a new JCat context.
///
/// The caller must free the returned pointer with `fu_jcat_context_free_rs`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fu_jcat_context_new_rs() -> *mut FuJcatContextRs {
    let ctx = jcat::Context::new();
    let keyring_path_cstr =
        CString::new(ctx.keyring_path().to_string_lossy().replace('\0', "")).ok();
    Box::into_raw(Box::new(FuJcatContextRs {
        inner: ctx,
        keyring_path_cstr,
    }))
}

/// Free a JCat context.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fu_jcat_context_free_rs(ctx: *mut FuJcatContextRs) {
    if !ctx.is_null() {
        unsafe { drop(Box::from_raw(ctx)) };
    }
}

// ---------------------------------------------------------------------------
// Context configuration
// ---------------------------------------------------------------------------

/// Add public key files from a directory.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fu_jcat_context_add_public_keys_rs(
    ctx: *mut FuJcatContextRs,
    path: *const c_char,
) {
    if ctx.is_null() || path.is_null() {
        return;
    }
    unsafe {
        let ctx = &mut *ctx;
        let path = CStr::from_ptr(path).to_string_lossy();
        ctx.inner.add_public_keys(&PathBuf::from(path.as_ref()));
    }
}

/// Set the keyring path.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fu_jcat_context_set_keyring_path_rs(
    ctx: *mut FuJcatContextRs,
    path: *const c_char,
) {
    if ctx.is_null() || path.is_null() {
        return;
    }
    unsafe {
        let ctx = &mut *ctx;
        let path_str = CStr::from_ptr(path).to_string_lossy();
        ctx.inner
            .set_keyring_path(&PathBuf::from(path_str.as_ref()));
        ctx.keyring_path_cstr = CString::new(path_str.replace('\0', "")).ok();
    }
}

/// Get the keyring path.
///
/// Returns a pointer to an internal null-terminated string. The pointer is
/// valid until the next call to `fu_jcat_context_set_keyring_path_rs` or
/// `fu_jcat_context_free_rs`. Returns NULL if the context is NULL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fu_jcat_context_get_keyring_path_rs(
    ctx: *const FuJcatContextRs,
) -> *const c_char {
    if ctx.is_null() {
        return std::ptr::null();
    }
    unsafe {
        let ctx = &*ctx;
        match &ctx.keyring_path_cstr {
            Some(cstr) => cstr.as_ptr(),
            None => std::ptr::null(),
        }
    }
}

/// Allow a blob kind for verification.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fu_jcat_context_allow_blob_kind_rs(ctx: *mut FuJcatContextRs, kind: u32) {
    if ctx.is_null() {
        return;
    }
    unsafe {
        let ctx = &mut *ctx;
        if let Some(kind) = jcat::BlobKind::try_from(kind).ok() {
            ctx.inner.allow_blob_kind(&[kind]);
        }
    }
}

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------

/// Verify a single blob against data.
///
/// On success, returns a heap-allocated `FuJcatResultRs`.
/// On failure, returns NULL and sets `*error_out` to a heap-allocated
/// error message string (caller must free with `free()`).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fu_jcat_context_verify_blob_rs(
    ctx: *mut FuJcatContextRs,
    data: *const u8,
    data_len: usize,
    blob_kind: u32,
    blob_data: *const u8,
    blob_data_len: usize,
    blob_is_utf8: bool,
    flags: u32,
    error_out: *mut *mut c_char,
) -> *mut FuJcatResultRs {
    if ctx.is_null() || data.is_null() || blob_data.is_null() {
        unsafe { set_error(error_out, "NULL pointer passed to verify_blob") };
        return std::ptr::null_mut();
    }
    unsafe {
        let ctx = &mut *ctx;
        let data = std::slice::from_raw_parts(data, data_len);
        let blob_data_slice = std::slice::from_raw_parts(blob_data, blob_data_len);

        let kind = match jcat::BlobKind::try_from(blob_kind).ok() {
            Some(k) => k,
            None => {
                set_error(error_out, &format!("unknown blob kind {blob_kind}"));
                return std::ptr::null_mut();
            }
        };
        let blob_flags = if blob_is_utf8 {
            jcat::BlobFlags::IS_UTF8
        } else {
            jcat::BlobFlags::NONE
        };
        let blob = jcat::Blob::new(kind, blob_data_slice.to_vec(), blob_flags);
        let verify_flags = jcat::VerifyFlags::from_bits_truncate(flags);

        match ctx.inner.verify_blob(data, &blob, verify_flags) {
            Ok(result) => Box::into_raw(Box::new(FuJcatResultRs::new(result))),
            Err(e) => {
                set_error(error_out, &e.to_string());
                std::ptr::null_mut()
            }
        }
    }
}

/// Verify an item (array of blobs) against data.
///
/// All checksum blobs must verify; at least one signature blob must verify.
///
/// `blobs` is a pointer to an array of `FuJcatBlobDescriptor` structs,
/// `blobs_len` is the number of elements. `item_id` is the item ID string.
///
/// On success, returns a heap-allocated array of `*mut FuJcatResultRs` via
/// `results_out`, with the count in `results_len_out`. The caller must free
/// each result with `fu_jcat_result_free_rs` and the array with `free()`.
///
/// On failure, returns `false` and sets `*error_out`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fu_jcat_context_verify_item_rs(
    ctx: *mut FuJcatContextRs,
    data: *const u8,
    data_len: usize,
    item_id: *const c_char,
    blobs: *const FuJcatBlobDescriptor,
    blobs_len: usize,
    flags: u32,
    results_out: *mut *mut *mut FuJcatResultRs,
    results_len_out: *mut usize,
    error_out: *mut *mut c_char,
) -> bool {
    if ctx.is_null()
        || data.is_null()
        || item_id.is_null()
        || blobs.is_null()
        || results_out.is_null()
        || results_len_out.is_null()
    {
        unsafe { set_error(error_out, "NULL pointer passed to verify_item") };
        return false;
    }
    unsafe {
        let ctx = &mut *ctx;
        let data = std::slice::from_raw_parts(data, data_len);
        let id = CStr::from_ptr(item_id).to_string_lossy();
        let blob_descs = std::slice::from_raw_parts(blobs, blobs_len);

        // Build the Item from the descriptor array.
        let mut item = jcat::Item::new(&id);
        for desc in blob_descs {
            if desc.data.is_null() {
                continue;
            }
            let kind = match jcat::BlobKind::try_from(desc.kind).ok() {
                Some(k) => k,
                None => continue, // skip unknown blob kinds
            };
            let blob_data = std::slice::from_raw_parts(desc.data, desc.data_len);
            let blob_flags = if desc.is_utf8 {
                jcat::BlobFlags::IS_UTF8
            } else {
                jcat::BlobFlags::NONE
            };
            let mut blob = jcat::Blob::new(kind, blob_data.to_vec(), blob_flags);
            if let Some(target) = jcat::BlobKind::try_from(desc.target).ok() {
                blob.set_target(target);
            }
            item.add_blobs([blob]);
        }

        let verify_flags = jcat::VerifyFlags::from_bits_truncate(flags);

        match ctx.inner.verify_item(data, &item, verify_flags) {
            Ok(results) => {
                let ptrs: Vec<*mut FuJcatResultRs> = results
                    .into_iter()
                    .map(|r| Box::into_raw(Box::new(FuJcatResultRs::new(r))))
                    .collect();
                let mut boxed = ptrs.into_boxed_slice();
                let len = boxed.len();
                let ptr = boxed.as_mut_ptr();
                std::mem::forget(boxed);
                *results_out = ptr;
                *results_len_out = len;
                true
            }
            Err(e) => {
                set_error(error_out, &e.to_string());
                *results_out = std::ptr::null_mut();
                *results_len_out = 0;
                false
            }
        }
    }
}

/// Verify a target item against an item containing signatures.
///
/// Same calling convention as `fu_jcat_context_verify_item_rs`, but takes
/// two sets of blob descriptors: one for the target item (containing expected
/// checksums) and one for the item being verified (containing checksums and
/// signatures).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fu_jcat_context_verify_target_rs(
    ctx: *mut FuJcatContextRs,
    target_item_id: *const c_char,
    target_blobs: *const FuJcatBlobDescriptor,
    target_blobs_len: usize,
    item_id: *const c_char,
    item_blobs: *const FuJcatBlobDescriptor,
    item_blobs_len: usize,
    flags: u32,
    results_out: *mut *mut *mut FuJcatResultRs,
    results_len_out: *mut usize,
    error_out: *mut *mut c_char,
) -> bool {
    if ctx.is_null()
        || target_item_id.is_null()
        || target_blobs.is_null()
        || item_id.is_null()
        || item_blobs.is_null()
        || results_out.is_null()
        || results_len_out.is_null()
    {
        unsafe { set_error(error_out, "NULL pointer passed to verify_target") };
        return false;
    }
    unsafe {
        let ctx = &mut *ctx;

        let build_item =
            |id_ptr: *const c_char, descs: *const FuJcatBlobDescriptor, len: usize| -> jcat::Item {
                let id = CStr::from_ptr(id_ptr).to_string_lossy();
                let descs = std::slice::from_raw_parts(descs, len);
                let mut item = jcat::Item::new(&id);
                for desc in descs {
                    if desc.data.is_null() {
                        continue;
                    }
                    let kind = match jcat::BlobKind::try_from(desc.kind).ok() {
                        Some(k) => k,
                        None => continue,
                    };
                    let blob_data = std::slice::from_raw_parts(desc.data, desc.data_len);
                    let blob_flags = if desc.is_utf8 {
                        jcat::BlobFlags::IS_UTF8
                    } else {
                        jcat::BlobFlags::NONE
                    };
                    let mut blob = jcat::Blob::new(kind, blob_data.to_vec(), blob_flags);
                    if let Some(target) = jcat::BlobKind::try_from(desc.target).ok() {
                        blob.set_target(target);
                    }
                    item.add_blobs([blob]);
                }
                item
            };

        let item_target = build_item(target_item_id, target_blobs, target_blobs_len);
        let item = build_item(item_id, item_blobs, item_blobs_len);
        let verify_flags = jcat::VerifyFlags::from_bits_truncate(flags);

        match ctx.inner.verify_target(&item_target, &item, verify_flags) {
            Ok(results) => {
                let ptrs: Vec<*mut FuJcatResultRs> = results
                    .into_iter()
                    .map(|r| Box::into_raw(Box::new(FuJcatResultRs::new(r))))
                    .collect();
                let mut boxed = ptrs.into_boxed_slice();
                let len = boxed.len();
                let ptr = boxed.as_mut_ptr();
                std::mem::forget(boxed);
                *results_out = ptr;
                *results_len_out = len;
                true
            }
            Err(e) => {
                set_error(error_out, &e.to_string());
                *results_out = std::ptr::null_mut();
                *results_len_out = 0;
                false
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Result accessors
// ---------------------------------------------------------------------------

/// Free a result.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fu_jcat_result_free_rs(result: *mut FuJcatResultRs) {
    if !result.is_null() {
        unsafe { drop(Box::from_raw(result)) };
    }
}

/// Get the timestamp from a result.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fu_jcat_result_get_timestamp_rs(result: *const FuJcatResultRs) -> i64 {
    if result.is_null() {
        return 0;
    }
    unsafe { (*result).inner.timestamp() }
}

/// Get the authority from a result.
///
/// Returns a pointer to an internal null-terminated string. The pointer is
/// valid until the result is freed. Returns NULL if no authority is set or
/// if the result pointer is NULL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fu_jcat_result_get_authority_rs(
    result: *const FuJcatResultRs,
) -> *const c_char {
    if result.is_null() {
        return std::ptr::null();
    }
    unsafe {
        match &(*result).authority_cstr {
            Some(cstr) => cstr.as_ptr(),
            None => std::ptr::null(),
        }
    }
}

/// Get the blob kind from a result.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fu_jcat_result_get_kind_rs(result: *const FuJcatResultRs) -> u32 {
    if result.is_null() {
        return 0;
    }
    unsafe { (*result).inner.kind().into() }
}

/// Get the verification method from a result.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fu_jcat_result_get_method_rs(result: *const FuJcatResultRs) -> u32 {
    if result.is_null() {
        return 0;
    }
    unsafe { (*result).inner.method().into() }
}

/// Free an array of results returned by verify_item or verify_target.
///
/// Frees each individual result and the array pointer itself.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fu_jcat_results_free_rs(
    results: *mut *mut FuJcatResultRs,
    results_len: usize,
) {
    if results.is_null() {
        return;
    }
    unsafe {
        for i in 0..results_len {
            let r = *results.add(i);
            if !r.is_null() {
                drop(Box::from_raw(r));
            }
        }
        // The array was allocated as a boxed slice, reconstruct and drop it.
        let _ = Box::from_raw(std::slice::from_raw_parts_mut(results, results_len));
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Helper to set the error output string.
unsafe fn set_error(error_out: *mut *mut c_char, msg: &str) {
    unsafe {
        if !error_out.is_null() {
            // Replace interior NUL bytes to avoid truncating the message.
            let sanitized = msg.replace('\0', "?");
            let c_msg = CString::new(sanitized).unwrap_or_default();
            *error_out = libc::strdup(c_msg.as_ptr());
        }
    }
}
