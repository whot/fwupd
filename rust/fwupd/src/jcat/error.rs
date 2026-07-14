/*
 * Copyright 2026 Red Hat
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

//! Error types for the JCat module.

use std::fmt;

/// Errors that can occur during JCat operations.
#[derive(Debug)]
pub enum Error {
    /// The requested blob kind is not allowed by the context.
    NotAllowed(String),
    /// No engine found for the requested blob kind.
    NotFound(String),
    /// The operation is not supported by this engine.
    NotSupported(String),
    /// The data is invalid or verification failed.
    InvalidData(String),
    /// An I/O error occurred.
    Io(std::io::Error),
    /// A JSON parsing error occurred.
    Json(serde_json::Error),
    /// An OpenSSL error occurred.
    OpenSSL(openssl::error::ErrorStack),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::NotAllowed(msg) => write!(f, "not allowed: {msg}"),
            Error::NotFound(msg) => write!(f, "not found: {msg}"),
            Error::NotSupported(msg) => write!(f, "not supported: {msg}"),
            Error::InvalidData(msg) => write!(f, "invalid data: {msg}"),
            Error::Io(e) => write!(f, "I/O error: {e}"),
            Error::Json(e) => write!(f, "JSON error: {e}"),
            Error::OpenSSL(e) => write!(f, "OpenSSL error: {e}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io(e) => Some(e),
            Error::Json(e) => Some(e),
            Error::OpenSSL(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error::Json(e)
    }
}

impl From<openssl::error::ErrorStack> for Error {
    fn from(e: openssl::error::ErrorStack) -> Self {
        Error::OpenSSL(e)
    }
}
