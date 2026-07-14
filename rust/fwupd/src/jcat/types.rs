/*
 * Copyright 2026 Red Hat
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

//! Core types and enumerations for the JCat module.

use std::fmt;

/// The kind of blob stored in a JCat item.
///
/// Each kind corresponds to a specific signature or checksum algorithm.
/// The discriminant values match the JSON wire format and C API.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum BlobKind {
    Sha256 = 1,
    Gpg = 2,
    Pkcs7 = 3,
    Sha1 = 4,
    BtManifest = 5,
    BtCheckpoint = 6,
    BtInclusionProof = 7,
    BtVerifier = 8,
    Ed25519 = 9,
    Sha512 = 10,
    BtLogindex = 11,
}

impl BlobKind {
    /// The number of defined blob kinds (upper bound for the allowlist bitfield).
    pub const COUNT: u32 = 12;
}

impl TryFrom<u32> for BlobKind {
    type Error = u32;

    fn try_from(v: u32) -> Result<Self, u32> {
        match v {
            1 => Ok(Self::Sha256),
            2 => Ok(Self::Gpg),
            3 => Ok(Self::Pkcs7),
            4 => Ok(Self::Sha1),
            5 => Ok(Self::BtManifest),
            6 => Ok(Self::BtCheckpoint),
            7 => Ok(Self::BtInclusionProof),
            8 => Ok(Self::BtVerifier),
            9 => Ok(Self::Ed25519),
            10 => Ok(Self::Sha512),
            11 => Ok(Self::BtLogindex),
            other => Err(other),
        }
    }
}

impl From<BlobKind> for u32 {
    fn from(kind: BlobKind) -> u32 {
        kind as u32
    }
}

impl fmt::Display for BlobKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Sha256 => "sha256",
            Self::Gpg => "gpg",
            Self::Pkcs7 => "pkcs7",
            Self::Sha1 => "sha1",
            Self::BtManifest => "bt-manifest",
            Self::BtCheckpoint => "bt-checkpoint",
            Self::BtInclusionProof => "bt-inclusion-proof",
            Self::BtVerifier => "bt-verifier",
            Self::Ed25519 => "ed25519",
            Self::Sha512 => "sha512",
            Self::BtLogindex => "bt-logindex",
        };
        f.write_str(s)
    }
}

impl std::str::FromStr for BlobKind {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, ()> {
        match s {
            "sha256" => Ok(Self::Sha256),
            "gpg" => Ok(Self::Gpg),
            "pkcs7" => Ok(Self::Pkcs7),
            "sha1" => Ok(Self::Sha1),
            "bt-manifest" => Ok(Self::BtManifest),
            "bt-checkpoint" => Ok(Self::BtCheckpoint),
            "bt-inclusion-proof" => Ok(Self::BtInclusionProof),
            "bt-verifier" => Ok(Self::BtVerifier),
            "ed25519" => Ok(Self::Ed25519),
            "sha512" => Ok(Self::Sha512),
            "bt-logindex" => Ok(Self::BtLogindex),
            _ => Err(()),
        }
    }
}

/// The verification method associated with an engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlobMethod {
    Checksum,
    Signature,
}

impl From<BlobMethod> for u32 {
    fn from(method: BlobMethod) -> u32 {
        match method {
            BlobMethod::Checksum => 1,
            BlobMethod::Signature => 2,
        }
    }
}

impl fmt::Display for BlobMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Checksum => "checksum",
            Self::Signature => "signature",
        };
        f.write_str(s)
    }
}

bitflags::bitflags! {
    /// Bitflags for a blob.
    ///
    /// Multiple flags can be combined with `|`.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct BlobFlags: u32 {
        const NONE = 0;
        /// The blob data is valid UTF-8 text.
        const IS_UTF8 = 1 << 0;
    }
}

bitflags::bitflags! {
    /// Bitflags controlling verification behavior.
    ///
    /// Multiple flags can be combined with `|`, e.g.
    /// `VerifyFlags::REQUIRE_CHECKSUM | VerifyFlags::REQUIRE_SIGNATURE`.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct VerifyFlags: u32 {
        const NONE = 0;
        /// Disable certificate time/expiry checks.
        const DISABLE_TIME_CHECKS = 1 << 0;
        /// Require at least one checksum to verify.
        const REQUIRE_CHECKSUM = 1 << 1;
        /// Require at least one signature to verify.
        const REQUIRE_SIGNATURE = 1 << 2;
        /// Only accept post-quantum signatures.
        const ONLY_PQ = 1 << 3;
    }
}

bitflags::bitflags! {
    /// Bitflags controlling signing behavior.
    ///
    /// Multiple flags can be combined with `|`, e.g.
    /// `SignFlags::ADD_TIMESTAMP | SignFlags::ADD_CERT`.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct SignFlags: u32 {
        const NONE = 0;
        /// Include a timestamp in the signature.
        const ADD_TIMESTAMP = 1 << 0;
        /// Include the signing certificate in the signature.
        const ADD_CERT = 1 << 1;
        /// Use post-quantum algorithms.
        const USE_PQ = 1 << 2;
    }
}
