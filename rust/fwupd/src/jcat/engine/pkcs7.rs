/*
 * Copyright 2026 Red Hat
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

//! PKCS#7/CMS signature engine backed by OpenSSL.

use foreign_types_shared::ForeignType;
use openssl::cms::{CMSOptions, CmsContentInfo};
use openssl::pkey::PKey;
use openssl::stack::Stack;
use openssl::x509::X509;
use openssl::x509::store::{X509Store, X509StoreBuilder};
use openssl::x509::verify::X509VerifyFlags;
use std::fs;
use std::path::PathBuf;

use crate::jcat::blob::Blob;
use crate::jcat::error::Error;
use crate::jcat::result::VerifyResult;
use crate::jcat::types::{BlobKind, BlobMethod, SignFlags, VerifyFlags};

use super::Engine;

// Raw FFI declarations for CMS functions not exposed by openssl-sys.
mod ffi {
    use std::os::raw::{c_int, c_long, c_uint, c_void};

    // Opaque types.
    #[repr(C)]
    pub struct CMS_SignerInfo {
        _opaque: [u8; 0],
    }

    #[repr(C)]
    pub struct OPENSSL_STACK {
        _opaque: [u8; 0],
    }

    unsafe extern "C" {
        // CMS signer info functions.
        pub fn CMS_get0_SignerInfos(cms: *mut openssl_sys::CMS_ContentInfo) -> *mut OPENSSL_STACK;
        pub fn CMS_signed_get_attr_by_NID(
            si: *mut CMS_SignerInfo,
            nid: c_int,
            lastpos: c_int,
        ) -> c_int;
        pub fn CMS_signed_get_attr(
            si: *mut CMS_SignerInfo,
            loc: c_int,
        ) -> *mut openssl_sys::X509_ATTRIBUTE;
        pub fn CMS_SignerInfo_get0_signer_id(
            si: *mut CMS_SignerInfo,
            keyid: *mut *mut openssl_sys::ASN1_OCTET_STRING,
            issuer: *mut *mut openssl_sys::X509_NAME,
            sno: *mut *mut openssl_sys::ASN1_INTEGER,
        ) -> c_int;

        // Stack functions.
        pub fn OPENSSL_sk_num(stack: *const OPENSSL_STACK) -> c_int;
        pub fn OPENSSL_sk_value(stack: *const OPENSSL_STACK, idx: c_int) -> *mut c_void;

        // X509 store param.
        pub fn X509_STORE_get0_param(
            store: *mut openssl_sys::X509_STORE,
        ) -> *mut openssl_sys::X509_VERIFY_PARAM;
        pub fn X509_VERIFY_PARAM_set_purpose(
            param: *mut openssl_sys::X509_VERIFY_PARAM,
            purpose: c_int,
        ) -> c_int;

        // X509 key usage.
        pub fn X509_get_key_usage(crt: *const openssl_sys::X509) -> c_uint;

        // X509_NAME formatting.
        pub fn X509_NAME_print_ex(
            bio: *mut openssl_sys::BIO,
            name: *const openssl_sys::X509_NAME,
            indent: c_int,
            flags: c_long,
        ) -> c_int;

        // BIO functions.
        pub fn BIO_free(bio: *mut openssl_sys::BIO) -> c_int;

        // ASN1 time conversion.
        pub fn ASN1_TIME_to_tm(s: *const openssl_sys::ASN1_TIME, tm: *mut libc::tm) -> c_int;

        // PEM output with explicit type string (for PKCS7 header).
        pub fn PEM_ASN1_write_bio(
            i2d: Option<unsafe extern "C" fn(*mut c_void, *mut *mut u8) -> c_int>,
            name: *const u8,
            bio: *mut openssl_sys::BIO,
            x: *mut c_void,
            enc: *const openssl_sys::EVP_CIPHER,
            kstr: *const u8,
            klen: c_int,
            cb: *mut c_void,
            u: *mut c_void,
        ) -> c_int;

        pub fn i2d_CMS_ContentInfo(
            cms: *mut openssl_sys::CMS_ContentInfo,
            out: *mut *mut u8,
        ) -> c_int;
    }

    // X509 purpose values.
    pub const X509_PURPOSE_ANY: c_int = 7;

    // X509_NAME_print_ex flag — verified against system headers.
    pub const XN_FLAG_RFC2253: c_long = 0x1110317;

    // NID for pkcs9_signingTime.
    pub const NID_PKCS9_SIGNINGTIME: c_int = 52;

    // ASN1 type tags.
    pub const V_ASN1_UTCTIME: c_int = 23;
    pub const V_ASN1_GENERALIZEDTIME: c_int = 24;

    // Key usage bits.
    pub const X509V3_KU_DIGITAL_SIGNATURE: c_uint = 0x0080;
    pub const X509V3_KU_KEY_CERT_SIGN: c_uint = 0x0004;

    // PEM type string for PKCS7 output (must be null-terminated).
    pub const PEM_STRING_PKCS7: &[u8] = b"PKCS7\0";
}

/// PKCS#7/CMS signature verification engine using OpenSSL.
pub struct Pkcs7Engine {
    certs: Vec<X509>,
    trust_store: Option<X509Store>,
    keyring_path: PathBuf,
}

impl std::fmt::Debug for Pkcs7Engine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pkcs7Engine")
            .field("certs_count", &self.certs.len())
            .field("keyring_path", &self.keyring_path)
            .finish()
    }
}

impl Pkcs7Engine {
    /// Create a new PKCS#7 engine with the given keyring path.
    pub fn new(keyring_path: PathBuf) -> Self {
        Self {
            certs: Vec::new(),
            trust_store: None,
            keyring_path,
        }
    }

    fn add_cert_pem(&mut self, pem: &[u8]) -> Result<(), Error> {
        let cert = X509::from_pem(pem)?;
        self.add_cert(cert)
    }

    fn add_cert_der(&mut self, der: &[u8]) -> Result<(), Error> {
        let cert = X509::from_der(der)?;
        self.add_cert(cert)
    }

    /// Add a certificate, checking key usage first and rejecting duplicates.
    fn add_cert(&mut self, cert: X509) -> Result<(), Error> {
        // Check key usage: must have digitalSignature or keyCertSign.
        unsafe {
            let key_usage = ffi::X509_get_key_usage(cert.as_ptr());
            if (key_usage & ffi::X509V3_KU_DIGITAL_SIGNATURE) == 0
                && (key_usage & ffi::X509V3_KU_KEY_CERT_SIGN) == 0
            {
                return Err(Error::InvalidData(format!(
                    "certificate not suitable for use [0x{key_usage:x}]"
                )));
            }
        }
        // Reject duplicates — the C code does this via X509_STORE_add_cert
        // which returns an error if the cert already exists.
        let dominated = cert.to_der().unwrap_or_default();
        if self
            .certs
            .iter()
            .any(|c| c.to_der().unwrap_or_default() == dominated)
        {
            return Err(Error::InvalidData(
                "failed to add to trust list: certificate already exists".into(),
            ));
        }
        self.certs.push(cert);
        // Invalidate cached trust store so it gets rebuilt.
        self.trust_store = None;
        Ok(())
    }

    /// Build (or return cached) trust store from loaded certificates.
    #[allow(dead_code)]
    fn ensure_trust_store(&mut self) -> Result<&X509Store, Error> {
        if self.trust_store.is_none() {
            let mut builder = X509StoreBuilder::new()?;
            for cert in &self.certs {
                builder.add_cert(cert.clone())?;
            }
            self.trust_store = Some(builder.build());
        }
        Ok(self.trust_store.as_ref().unwrap())
    }

    /// Core CMS verification logic.
    fn verify_cms(
        &self,
        data: &[u8],
        signature_pem: &[u8],
        self_signed_cert: Option<&X509>,
        flags: VerifyFlags,
    ) -> Result<VerifyResult, Error> {
        let mut cms = CmsContentInfo::from_pem(signature_pem)
            .map_err(|e| Error::InvalidData(format!("failed to parse PKCS7 signature: {e}")))?;

        // Check for zero signers before verification (matches C behavior).
        unsafe {
            let infos = ffi::CMS_get0_SignerInfos(cms.as_ptr());
            if infos.is_null() || ffi::OPENSSL_sk_num(infos) <= 0 {
                return Err(Error::InvalidData("no PKCS7 signatures found".into()));
            }
        }

        // The C code uses only CMS_BINARY as verify flags — no NOINTERN.
        let cms_flags = CMSOptions::BINARY;

        // Build the trust store for this verification.
        let store = if let Some(cert) = self_signed_cert {
            // Self-signed verification: build a temporary store with just this cert.
            let mut builder = X509StoreBuilder::new()?;
            builder.add_cert(cert.clone())?;
            unsafe {
                let param = ffi::X509_STORE_get0_param(builder.as_ptr());
                ffi::X509_VERIFY_PARAM_set_purpose(param, ffi::X509_PURPOSE_ANY);
            }
            if flags.contains(VerifyFlags::DISABLE_TIME_CHECKS) {
                builder.set_flags(X509VerifyFlags::NO_CHECK_TIME)?;
            }
            builder.build()
        } else {
            // Public key verification: build store from loaded certs.
            let mut builder = X509StoreBuilder::new()?;
            for cert in &self.certs {
                builder.add_cert(cert.clone())?;
            }
            unsafe {
                let param = ffi::X509_STORE_get0_param(builder.as_ptr());
                ffi::X509_VERIFY_PARAM_set_purpose(param, ffi::X509_PURPOSE_ANY);
            }
            if flags.contains(VerifyFlags::DISABLE_TIME_CHECKS) {
                builder.set_flags(X509VerifyFlags::NO_CHECK_TIME)?;
            }
            builder.build()
        };

        // Build signer certs stack for self-signed mode.
        let signer_certs = if let Some(cert) = self_signed_cert {
            let mut stack = Stack::new()?;
            stack.push(cert.clone())?;
            Some(stack)
        } else {
            None
        };

        let signer_ref = signer_certs.as_deref();
        cms.verify(signer_ref, Some(&store), Some(data), None, cms_flags)
            .map_err(|e| Error::InvalidData(format!("failed to verify data: {e}")))?;

        // Extract signer info — these now return errors on malformed data,
        // matching the C behavior.
        let timestamp = self.extract_signing_time(&cms)?;
        let authority = self.extract_authority(&cms)?;

        Ok(VerifyResult::new_signature(
            BlobKind::Pkcs7,
            timestamp,
            authority,
        ))
    }

    /// Extract the signing time from CMS signer infos.
    ///
    /// Returns an error if a signing time attribute exists but has an
    /// invalid type or cannot be converted, matching the C behavior.
    fn extract_signing_time(&self, cms: &CmsContentInfo) -> Result<i64, Error> {
        unsafe {
            let infos = ffi::CMS_get0_SignerInfos(cms.as_ptr());
            if infos.is_null() {
                return Ok(0);
            }

            let count = ffi::OPENSSL_sk_num(infos);
            let mut newest: i64 = 0;

            for i in 0..count {
                let info = ffi::OPENSSL_sk_value(infos, i) as *mut ffi::CMS_SignerInfo;
                if info.is_null() {
                    continue;
                }

                let loc = ffi::CMS_signed_get_attr_by_NID(info, ffi::NID_PKCS9_SIGNINGTIME, -1);
                if loc < 0 {
                    continue;
                }
                let attr = ffi::CMS_signed_get_attr(info, loc);
                if attr.is_null() {
                    continue;
                }
                let stime = openssl_sys::X509_ATTRIBUTE_get0_type(attr, 0);
                if stime.is_null() {
                    continue;
                }

                let stime_type = (*stime).type_;
                if stime_type != ffi::V_ASN1_UTCTIME && stime_type != ffi::V_ASN1_GENERALIZEDTIME {
                    // C code returns a hard error here.
                    return Err(Error::InvalidData(
                        "failed to extract timestamp: unexpected ASN1 type".into(),
                    ));
                }

                let asn1_time = (*stime).value.asn1_string as *const openssl_sys::ASN1_TIME;
                if asn1_time.is_null() {
                    continue;
                }

                let mut tm: libc::tm = std::mem::zeroed();
                if ffi::ASN1_TIME_to_tm(asn1_time, &mut tm) == 0 {
                    // C code returns a hard error here.
                    return Err(Error::InvalidData("failed to convert timestamp".into()));
                }
                let t = libc::timegm(&mut tm);
                if t == -1 {
                    return Err(Error::InvalidData("failed to convert signing time".into()));
                }
                if t > newest || newest == 0 {
                    newest = t;
                }
            }

            Ok(newest)
        }
    }

    /// Extract the authority (issuer DN) from the CMS signer infos.
    ///
    /// Returns an error if signer info extraction fails, matching C behavior.
    fn extract_authority(&self, cms: &CmsContentInfo) -> Result<Option<String>, Error> {
        unsafe {
            let infos = ffi::CMS_get0_SignerInfos(cms.as_ptr());
            if infos.is_null() {
                return Ok(None);
            }

            let count = ffi::OPENSSL_sk_num(infos);
            let mut authority = String::new();

            for i in 0..count {
                let info = ffi::OPENSSL_sk_value(infos, i) as *mut ffi::CMS_SignerInfo;
                if info.is_null() {
                    continue;
                }

                let mut issuer_name: *mut openssl_sys::X509_NAME = std::ptr::null_mut();
                if ffi::CMS_SignerInfo_get0_signer_id(
                    info,
                    std::ptr::null_mut(),
                    &mut issuer_name,
                    std::ptr::null_mut(),
                ) == 0
                {
                    return Err(Error::InvalidData("failed to extract issuer name".into()));
                }
                if issuer_name.is_null() {
                    continue;
                }

                let bio = openssl_sys::BIO_new(openssl_sys::BIO_s_mem());
                if bio.is_null() {
                    continue;
                }
                let rc = ffi::X509_NAME_print_ex(bio, issuer_name, 0, ffi::XN_FLAG_RFC2253);
                if rc == -1 {
                    ffi::BIO_free(bio);
                    return Err(Error::InvalidData("failed to print issuer name".into()));
                }
                if rc >= 0 {
                    let mut buf_ptr: *mut std::ffi::c_char = std::ptr::null_mut();
                    let len = openssl_sys::BIO_get_mem_data(bio, &mut buf_ptr);
                    if len > 0 && !buf_ptr.is_null() {
                        let slice = std::slice::from_raw_parts(buf_ptr as *const u8, len as usize);
                        if let Ok(s) = std::str::from_utf8(slice) {
                            authority = s.to_string();
                        }
                    }
                }
                ffi::BIO_free(bio);
            }

            if authority.is_empty() {
                Ok(None)
            } else {
                Ok(Some(authority))
            }
        }
    }

    fn load_or_generate_self_sign_keys(&self) -> Result<(Vec<u8>, Vec<u8>), Error> {
        let pki_dir = self.keyring_path.join("pki");
        let privkey_path = pki_dir.join("secret.key");
        let cert_path = pki_dir.join("client.pem");

        let privkey_pem = if privkey_path.exists() {
            fs::read(&privkey_path)?
        } else {
            let rsa = openssl::rsa::Rsa::generate(3072)?;
            let pkey = PKey::from_rsa(rsa)?;
            let pem = pkey.private_key_to_pem_pkcs8()?;
            fs::create_dir_all(&pki_dir)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                let mut f = fs::OpenOptions::new()
                    .write(true)
                    .create(true)
                    .truncate(true)
                    .mode(0o600)
                    .open(&privkey_path)?;
                std::io::Write::write_all(&mut f, &pem)?;
            }
            #[cfg(not(unix))]
            fs::write(&privkey_path, &pem)?;
            pem
        };

        let cert_pem = if cert_path.exists() {
            fs::read(&cert_path)?
        } else {
            let pkey = PKey::private_key_from_pem(&privkey_pem)?;
            let cert_pem = self.create_self_signed_cert(&pkey)?;
            fs::create_dir_all(&pki_dir)?;
            fs::write(&cert_path, &cert_pem)?;
            cert_pem
        };

        Ok((cert_pem, privkey_pem))
    }

    fn create_self_signed_cert(
        &self,
        pkey: &PKey<openssl::pkey::Private>,
    ) -> Result<Vec<u8>, Error> {
        use openssl::asn1::Asn1Time;
        use openssl::bn::BigNum;
        use openssl::hash::MessageDigest;
        use openssl::x509::X509Builder;
        use openssl::x509::extension::{BasicConstraints, KeyUsage, SubjectKeyIdentifier};

        let mut builder = X509Builder::new()?;
        builder.set_version(2)?;
        builder.set_pubkey(pkey)?;

        let mut serial_bn = BigNum::new()?;
        serial_bn.rand(159, openssl::bn::MsbOption::MAYBE_ZERO, false)?;
        let serial = serial_bn.to_asn1_integer()?;
        builder.set_serial_number(&serial)?;

        let not_before = Asn1Time::days_from_now(0)?;
        builder.set_not_before(&not_before)?;

        let not_after = Asn1Time::from_str_x509("99991231235959Z")?;
        builder.set_not_after(&not_after)?;

        let bc = BasicConstraints::new().build()?;
        builder.append_extension(bc)?;

        let ku = KeyUsage::new().digital_signature().build()?;
        builder.append_extension(ku)?;

        let ctx = builder.x509v3_context(None, None);
        let skid = SubjectKeyIdentifier::new().build(&ctx)?;
        builder.append_extension(skid)?;

        builder.sign(pkey, MessageDigest::sha256())?;
        let cert = builder.build();
        Ok(cert.to_pem()?)
    }

    /// Encode CMS to PEM with `-----BEGIN PKCS7-----` header (matching C output).
    fn cms_to_pkcs7_pem(cms: &CmsContentInfo) -> Result<String, Error> {
        unsafe {
            let bio = openssl_sys::BIO_new(openssl_sys::BIO_s_mem());
            if bio.is_null() {
                return Err(Error::InvalidData("failed to create BIO".into()));
            }

            // PEM_ASN1_write_bio expects i2d_of_void, cast via Option<fn>.
            let i2d_fn: Option<unsafe extern "C" fn(*mut std::ffi::c_void, *mut *mut u8) -> i32> =
                Some(std::mem::transmute::<
                    unsafe extern "C" fn(*mut openssl_sys::CMS_ContentInfo, *mut *mut u8) -> i32,
                    unsafe extern "C" fn(*mut std::ffi::c_void, *mut *mut u8) -> i32,
                >(ffi::i2d_CMS_ContentInfo));

            let rc = ffi::PEM_ASN1_write_bio(
                i2d_fn,
                ffi::PEM_STRING_PKCS7.as_ptr(),
                bio,
                cms.as_ptr() as *mut _,
                std::ptr::null(),
                std::ptr::null(),
                0,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            );
            if rc == 0 {
                ffi::BIO_free(bio);
                return Err(Error::InvalidData("failed to encode PKCS7".into()));
            }

            // NULL-terminate and read.
            openssl_sys::BIO_write(bio, b"\0".as_ptr() as *const _, 1);
            let mut buf_ptr: *mut std::ffi::c_char = std::ptr::null_mut();
            let len = openssl_sys::BIO_get_mem_data(bio, &mut buf_ptr);
            let result = if len > 0 && !buf_ptr.is_null() {
                // len includes the null terminator we wrote.
                let slice = std::slice::from_raw_parts(buf_ptr as *const u8, (len - 1) as usize);
                String::from_utf8_lossy(slice).into_owned()
            } else {
                ffi::BIO_free(bio);
                return Err(Error::InvalidData("empty PKCS7 output".into()));
            };
            ffi::BIO_free(bio);
            Ok(result)
        }
    }
}

impl Engine for Pkcs7Engine {
    fn kind(&self) -> BlobKind {
        BlobKind::Pkcs7
    }

    fn method(&self) -> BlobMethod {
        BlobMethod::Signature
    }

    fn setup(&mut self, public_key_paths: &[PathBuf]) -> Result<(), Error> {
        for path in public_key_paths {
            let path_str = path.to_string_lossy();
            if path_str.ends_with(".pem") || path_str.ends_with(".crt") {
                let data = fs::read(path).map_err(|e| {
                    Error::Io(std::io::Error::new(
                        e.kind(),
                        format!("{}: {e}", path.display()),
                    ))
                })?;
                self.add_cert_pem(&data)?;
            } else if path_str.ends_with(".cer") || path_str.ends_with(".der") {
                let data = fs::read(path).map_err(|e| {
                    Error::Io(std::io::Error::new(
                        e.kind(),
                        format!("{}: {e}", path.display()),
                    ))
                })?;
                self.add_cert_der(&data)?;
            }
            // Silently ignore other file types.
        }
        Ok(())
    }

    fn self_verify(
        &self,
        data: &[u8],
        signature: &[u8],
        flags: VerifyFlags,
    ) -> Result<VerifyResult, Error> {
        let cert_path = self.keyring_path.join("pki").join("client.pem");
        let cert_pem = fs::read(&cert_path).map_err(|e| {
            Error::InvalidData(format!(
                "failed to read client cert {}: {e}",
                cert_path.display()
            ))
        })?;
        let cert = X509::from_pem(&cert_pem)?;
        self.verify_cms(data, signature, Some(&cert), flags)
    }

    fn self_sign(&self, data: &[u8], flags: SignFlags) -> Result<Blob, Error> {
        let (cert_pem, privkey_pem) = self.load_or_generate_self_sign_keys()?;
        self.pubkey_sign(data, &cert_pem, &privkey_pem, flags)
    }

    fn pubkey_verify(
        &self,
        data: &[u8],
        signature: &[u8],
        flags: VerifyFlags,
    ) -> Result<VerifyResult, Error> {
        self.verify_cms(data, signature, None, flags)
    }

    fn pubkey_sign(
        &self,
        data: &[u8],
        cert_pem: &[u8],
        privkey_pem: &[u8],
        flags: SignFlags,
    ) -> Result<Blob, Error> {
        if data.is_empty() {
            return Err(Error::NotSupported("nothing to do".into()));
        }

        let pkey = PKey::private_key_from_pem(privkey_pem)?;
        let cert = X509::from_pem(cert_pem)?;

        let mut cms_flags = CMSOptions::BINARY | CMSOptions::DETACHED | CMSOptions::NOSMIMECAP;

        if !flags.contains(SignFlags::ADD_TIMESTAMP) {
            // Use NOATTR to suppress all signed attributes including signingTime.
            // The C code uses CMS_NO_SIGNING_TIME on OpenSSL >= 3.5, but falls back
            // to returning an error on older versions. NOATTR is a reasonable
            // approximation that works on all versions.
            cms_flags |= CMSOptions::NOATTR;
        }

        if !flags.contains(SignFlags::ADD_CERT) {
            cms_flags |= CMSOptions::CMS_NOCERTS;
        }

        let cms = CmsContentInfo::sign(Some(&cert), Some(&pkey), None, Some(data), cms_flags)?;

        // Encode with PKCS7 PEM header to match C output format.
        let pem_str = Self::cms_to_pkcs7_pem(&cms)?;

        Ok(Blob::new_utf8(BlobKind::Pkcs7, &pem_str))
    }

    fn add_public_key_raw(&mut self, blob: &[u8]) -> Result<(), Error> {
        self.add_cert_pem(blob)
    }

    fn set_keyring_path(&mut self, path: &std::path::Path) {
        self.keyring_path = path.to_path_buf();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pkcs7_self_sign_and_verify() {
        let dir = tempfile::tempdir().unwrap();
        let engine = Pkcs7Engine::new(dir.path().to_path_buf());

        let data = b"hello world";
        let blob = engine.self_sign(data, SignFlags::ADD_TIMESTAMP).unwrap();

        // Verify the PEM output has PKCS7 header.
        let pem_str = blob.data_as_string().to_string();
        assert!(
            pem_str.contains("-----BEGIN PKCS7-----"),
            "expected PKCS7 header, got: {}",
            &pem_str[..60.min(pem_str.len())]
        );

        let result = engine
            .self_verify(data, blob.data(), VerifyFlags::NONE)
            .unwrap();
        assert_eq!(result.kind(), BlobKind::Pkcs7);
        assert_eq!(result.method(), BlobMethod::Signature);
    }

    #[test]
    fn pkcs7_self_verify_wrong_data() {
        let dir = tempfile::tempdir().unwrap();
        let engine = Pkcs7Engine::new(dir.path().to_path_buf());

        let data = b"hello world";
        let blob = engine.self_sign(data, SignFlags::ADD_TIMESTAMP).unwrap();

        let result = engine.self_verify(b"wrong data", blob.data(), VerifyFlags::NONE);
        assert!(result.is_err());
    }
}
