/*
 * Copyright 2026 Red Hat
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

//! FFI wrappers for JCat engine operations.
//!
//! The engine is not directly exposed as an opaque type in the FFI because
//! the C code accesses engines through the context. The engine-level
//! operations (self_verify, self_sign, pubkey_verify, pubkey_sign) are
//! exposed via the context FFI wrappers above.

// Engine-level FFI wrappers are provided through the context module.
// This module exists for future expansion if direct engine access is needed.
