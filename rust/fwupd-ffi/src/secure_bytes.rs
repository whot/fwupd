/*
 * Copyright 2026 Red Hat
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

//! C-compatible FFI wrappers for `SecureBytes`.

use std::ptr;

use crate::glib::GError;
use fwupd::secure_bytes::{BorrowedSecureBytes, SecureBytes};

/// Create a new `SecureBytes` from a buffer.
///
/// The input buffer is copied into the `SecureBytes` object.
/// Returns NULL on allocation failure or if buf is NULL and len > 0.
///
/// # Safety
/// - `buf` must point to `len` readable bytes (or be NULL if `len` is 0).
#[no_mangle]
pub unsafe extern "C" fn fu_rs_secure_bytes_new(buf: *const u8, len: usize) -> *mut SecureBytes {
    if len > 0 && buf.is_null() {
        return ptr::null_mut();
    }

    let bytes = if buf.is_null() || len == 0 {
        Vec::new()
    } else {
        unsafe { std::slice::from_raw_parts(buf, len) }.to_vec()
    };

    Box::into_raw(Box::new(SecureBytes::take(bytes)))
}

/// Get the size of a `SecureBytes` object.
///
/// Returns the buffer size in bytes, or 0 if `secure_bytes` is NULL.
///
/// # Safety
/// - `secure_bytes` must be a valid pointer returned by `fu_rs_secure_bytes_new`,
///   or NULL.
#[no_mangle]
pub unsafe extern "C" fn fu_rs_secure_bytes_get_size(secure_bytes: *const SecureBytes) -> usize {
    if secure_bytes.is_null() {
        return 0;
    }

    let secure = unsafe { &*secure_bytes };
    secure.data().len()
}

/// Get a pointer to the data of a `SecureBytes` object.
///
/// Returns a pointer to the internal buffer, or NULL if `secure_bytes` is NULL.
/// Use `fu_rs_secure_bytes_get_size()` to get the buffer length.
///
/// The returned buffer pointer is valid only until the `SecureBytes` is freed
/// or wiped. The caller must NOT free this buffer.
///
/// # Safety
/// - `secure_bytes` must be a valid pointer returned by `fu_rs_secure_bytes_new`,
///   or NULL.
#[no_mangle]
pub unsafe extern "C" fn fu_rs_secure_bytes_get_data(
    secure_bytes: *const SecureBytes,
) -> *const u8 {
    if secure_bytes.is_null() {
        return ptr::null();
    }

    let secure = unsafe { &*secure_bytes };
    secure.data().as_ptr()
}

/// Wipe the contents of a `SecureBytes` object to zeros.
///
/// The buffer remains valid and retains its length, but all bytes are set to zero.
/// Returns 0 on success, -1 on error.
///
/// # Safety
/// - `secure_bytes` must be a valid pointer returned by `fu_rs_secure_bytes_new`.
#[no_mangle]
pub unsafe extern "C" fn fu_rs_secure_bytes_wipe(
    secure_bytes: *mut SecureBytes,
    error: *mut *mut GError,
) -> i32 {
    if secure_bytes.is_null() {
        let e = fwupd::Error::new(fwupd::ErrorKind::InvalidData, "NULL SecureBytes pointer");
        GError::convert(error, &e);
        return -1;
    }

    let secure = unsafe { &mut *secure_bytes };
    secure.wipe();

    0
}

/// Free a `SecureBytes` object.
///
/// The buffer will be wiped to zeros before being freed.
///
/// # Safety
/// `secure_bytes` must have been returned by `fu_rs_secure_bytes_new`, or be NULL.
#[no_mangle]
pub unsafe extern "C" fn fu_rs_secure_bytes_free(secure_bytes: *mut SecureBytes) {
    if !secure_bytes.is_null() {
        drop(unsafe { Box::from_raw(secure_bytes) });
    }
}

/// Create a new `BorrowedSecureBytes` wrapping an existing buffer.
///
/// The buffer is NOT copied - the `BorrowedSecureBytes` will wipe the original
/// buffer when freed. The caller retains ownership of the buffer but must NOT
/// free it before calling `fu_rs_borrowed_secure_bytes_free()`.
///
/// Returns NULL if buf is NULL and len > 0.
///
/// # Safety
/// - `buf` must point to `len` readable and writable bytes (or be NULL if `len` is 0).
/// - The buffer must remain valid until `fu_rs_borrowed_secure_bytes_free` is called.
/// - The buffer must NOT be accessed from C after this call until freed.
#[no_mangle]
pub unsafe extern "C" fn fu_rs_borrowed_secure_bytes_new(
    buf: *mut u8,
    len: usize,
) -> *mut BorrowedSecureBytes<'static> {
    if len > 0 && buf.is_null() {
        return ptr::null_mut();
    }

    let slice = if buf.is_null() || len == 0 {
        &mut []
    } else {
        // SAFETY: Caller guarantees buf points to len valid bytes
        // We're using 'static here which is technically a lie, but it's the only
        // way to box it. The caller MUST ensure the buffer lives until free().
        unsafe { std::slice::from_raw_parts_mut(buf, len) }
    };

    Box::into_raw(Box::new(BorrowedSecureBytes::from(slice)))
}

/// Get the size of a `BorrowedSecureBytes` object.
///
/// Returns the buffer size in bytes, or 0 if `borrowed_secure_bytes` is NULL.
///
/// # Safety
/// - `borrowed_secure_bytes` must be a valid pointer returned by
///   `fu_rs_borrowed_secure_bytes_new`, or NULL.
#[no_mangle]
pub unsafe extern "C" fn fu_rs_borrowed_secure_bytes_get_size(
    borrowed_secure_bytes: *const BorrowedSecureBytes,
) -> usize {
    if borrowed_secure_bytes.is_null() {
        return 0;
    }

    let secure = unsafe { &*borrowed_secure_bytes };
    secure.data().len()
}

/// Get a pointer to the data of a `BorrowedSecureBytes` object.
///
/// Returns a pointer to the internal buffer, or NULL if `borrowed_secure_bytes` is NULL.
/// Use `fu_rs_borrowed_secure_bytes_get_size()` to get the buffer length.
///
/// The returned buffer pointer is the same as the original buffer passed to
/// `fu_rs_borrowed_secure_bytes_new()`. It is valid only until the `BorrowedSecureBytes`
/// is freed or wiped. The caller must NOT free this buffer.
///
/// # Safety
/// - `borrowed_secure_bytes` must be a valid pointer returned by
///   `fu_rs_borrowed_secure_bytes_new`, or NULL.
#[no_mangle]
pub unsafe extern "C" fn fu_rs_borrowed_secure_bytes_get_data(
    borrowed_secure_bytes: *const BorrowedSecureBytes,
) -> *const u8 {
    if borrowed_secure_bytes.is_null() {
        return ptr::null();
    }

    let secure = unsafe { &*borrowed_secure_bytes };
    secure.data().as_ptr()
}

/// Wipe the contents of a `BorrowedSecureBytes` object to zeros.
///
/// The buffer remains valid and retains its length, but all bytes are set to zero.
/// This also affects the original buffer that was passed to `fu_rs_borrowed_secure_bytes_new()`.
/// Returns 0 on success, -1 on error.
///
/// # Safety
/// - `borrowed_secure_bytes` must be a valid pointer returned by
///   `fu_rs_borrowed_secure_bytes_new`.
#[no_mangle]
pub unsafe extern "C" fn fu_rs_borrowed_secure_bytes_wipe(
    borrowed_secure_bytes: *mut BorrowedSecureBytes,
    error: *mut *mut GError,
) -> i32 {
    if borrowed_secure_bytes.is_null() {
        let e = fwupd::Error::new(
            fwupd::ErrorKind::InvalidData,
            "NULL BorrowedSecureBytes pointer",
        );
        GError::convert(error, &e);
        return -1;
    }

    let secure = unsafe { &mut *borrowed_secure_bytes };
    secure.wipe();

    0
}

/// Free a `BorrowedSecureBytes` object.
///
/// The wrapped buffer will be wiped to zeros before the wrapper is freed.
/// The original buffer remains valid after this call (but wiped), and the
/// caller is responsible for freeing it if necessary.
///
/// # Safety
/// `borrowed_secure_bytes` must have been returned by
/// `fu_rs_borrowed_secure_bytes_new`, or be NULL.
#[no_mangle]
pub unsafe extern "C" fn fu_rs_borrowed_secure_bytes_free(
    borrowed_secure_bytes: *mut BorrowedSecureBytes,
) {
    if !borrowed_secure_bytes.is_null() {
        drop(unsafe { Box::from_raw(borrowed_secure_bytes) });
    }
}
