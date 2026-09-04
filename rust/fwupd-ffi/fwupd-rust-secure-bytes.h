/*
 * Copyright 2026 Red Hat
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 *
 * C header for the Rust SecureBytes FFI functions in the fwupd-ffi crate.
 * This header is hand-written; keep it in sync with
 * rust/fwupd-ffi/src/secure_bytes.rs.
 */

#pragma once

#include <glib.h>

G_BEGIN_DECLS

/**
 * FuRsSecureBytes:
 *
 * An opaque buffer that automatically wipes its content to zeros
 * before being freed. Can be used for keys, tokens, or passwords
 * to prevent plaintext from remaining in heap memory.
 *
 * This type owns its buffer. See FuRsBorrowedSecureBytes for a
 * borrowed variant.
 */
typedef struct FuRsSecureBytes FuRsSecureBytes;

FuRsSecureBytes *
fu_rs_secure_bytes_new(const guint8 *buf, gsize len);

gsize
fu_rs_secure_bytes_get_size(const FuRsSecureBytes *secure_bytes);

const guint8 *
fu_rs_secure_bytes_get_data(const FuRsSecureBytes *secure_bytes);

gint32
fu_rs_secure_bytes_wipe(FuRsSecureBytes *secure_bytes, GError **error);

void
fu_rs_secure_bytes_free(FuRsSecureBytes *secure_bytes);

G_DEFINE_AUTOPTR_CLEANUP_FUNC(FuRsSecureBytes, fu_rs_secure_bytes_free)

/**
 * FuRsBorrowedSecureBytes:
 *
 * A borrowed buffer wrapper that automatically wipes the buffer to zeros
 * before being freed. Unlike FuRsSecureBytes, this does NOT own the buffer.
 * The wrapped buffer is wiped when this object is freed, but the caller
 * remains responsible for freeing the actual buffer memory.
 *
 * Use this when you have an existing buffer (e.g., allocated with g_malloc)
 * and want to ensure it's wiped after use while retaining ownership.
 */
typedef struct FuRsBorrowedSecureBytes FuRsBorrowedSecureBytes;

FuRsBorrowedSecureBytes *
fu_rs_borrowed_secure_bytes_new(guint8 *buf, gsize len);

gsize
fu_rs_borrowed_secure_bytes_get_size(const FuRsBorrowedSecureBytes *borrowed_secure_bytes);

const guint8 *
fu_rs_borrowed_secure_bytes_get_data(const FuRsBorrowedSecureBytes *borrowed_secure_bytes);

gint32
fu_rs_borrowed_secure_bytes_wipe(FuRsBorrowedSecureBytes *borrowed_secure_bytes, GError **error);

void
fu_rs_borrowed_secure_bytes_free(FuRsBorrowedSecureBytes *borrowed_secure_bytes);

G_DEFINE_AUTOPTR_CLEANUP_FUNC(FuRsBorrowedSecureBytes, fu_rs_borrowed_secure_bytes_free)

G_END_DECLS
