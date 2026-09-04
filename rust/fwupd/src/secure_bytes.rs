/*
 * Copyright 2026 Red Hat
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

//! A buffer that automatically wipes its content (to zero)
//! before dropping. Can be used for keys, tokens or passwords
//! so that the plaintext is not left behind in heap memory.

#[cfg(supports_rust_1_85)]
use zeroize::Zeroize;

/// A buffer that automatically wipes its content (to zero)
/// before dropping. Can be used for keys, tokens or passwords
/// so that the plaintext is not left behind in heap memory.
pub struct SecureBytes {
    data: Vec<u8>,
}

/// A buffer that automatically wipes its content (to zero)
/// before dropping. This is the borrowed version where the
/// caller is responsible for the buffer itself.
///
/// See [`SecureBytes`] for the owned version.
pub struct BorrowedSecureBytes<'a> {
    data: &'a mut [u8],
}

impl SecureBytes {
    /// Take the given buffer and return a [`SecureBytes`].
    /// Once dropped, the buffer will be wiped to zeros.
    #[must_use]
    pub fn take(data: Vec<u8>) -> Self {
        Self { data }
    }

    /// Wipe the buffer contents to zero. The buffer remains
    /// valid (and of equal length) but the content is no
    /// longer available.
    #[cfg(supports_rust_1_85)]
    pub fn wipe(&mut self) {
        self.data.as_mut_slice().zeroize();
    }

    /// Wipe the buffer contents to zero. The buffer remains
    /// valid (and of equal length) but the content is no
    /// longer available.
    ///
    /// # Warning
    ///
    /// This is the fallback version for older rust versions
    /// and is not cryptographically reliable.
    #[cfg(not(supports_rust_1_85))]
    pub fn wipe(&mut self) {
        self.data.fill(0);
    }

    /// Return the data of the buffer.
    #[must_use]
    pub fn data(&self) -> &[u8] {
        &self.data
    }
}

impl Drop for SecureBytes {
    fn drop(&mut self) {
        self.wipe();
    }
}

impl<'a> BorrowedSecureBytes<'a> {
    /// Take the given buffer and return a [`SecureBytes`].
    /// Once dropped, the buffer will be wiped to zeros.
    pub fn from(data: &'a mut [u8]) -> Self {
        Self { data }
    }

    /// Wipe the buffer contents to zero. The buffer remains
    /// valid (and of equal length) but the content is no
    /// longer available.
    #[cfg(supports_rust_1_85)]
    pub fn wipe(&mut self) {
        self.data.zeroize();
    }

    /// Wipe the buffer contents to zero. The buffer remains
    /// valid (and of equal length) but the content is no
    /// longer available.
    ///
    /// # Warning
    ///
    /// This is the fallback version for older rust versions
    /// and is not cryptographically reliable.
    #[cfg(not(supports_rust_1_85))]
    pub fn wipe(&mut self) {
        self.data.fill(0);
    }

    /// Return the data of the buffer.
    #[must_use]
    pub fn data(&self) -> &[u8] {
        self.data
    }
}

impl Drop for BorrowedSecureBytes<'_> {
    fn drop(&mut self) {
        self.wipe();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_take_and_contents() {
        let data = vec![1, 2, 3, 4, 5];
        let secure = SecureBytes::take(data.clone());
        assert_eq!(secure.data(), &[1, 2, 3, 4, 5]);
    }

    #[test]
    fn test_empty_buffer() {
        let secure = SecureBytes::take(vec![]);
        assert_eq!(secure.data(), &[]);
    }

    #[test]
    fn test_manual_wipe() {
        let data = vec![0x42, 0x43, 0x44, 0x45];
        let mut secure = SecureBytes::take(data);

        assert_eq!(secure.data(), &[0x42, 0x43, 0x44, 0x45]);

        secure.wipe();

        assert_eq!(secure.data(), &[0, 0, 0, 0]);
    }

    #[test]
    fn test_wipe_preserves_length() {
        let data = vec![0xAA; 100];
        let mut secure = SecureBytes::take(data);

        assert_eq!(secure.data().len(), 100);

        secure.wipe();

        assert_eq!(secure.data().len(), 100);
        assert!(secure.data().iter().all(|&b| b == 0));
    }

    #[test]
    fn test_drop_calls_wipe() {
        // This test verifies that Drop is implemented and that dropping
        // a SecureBytes doesn't panic. The actual wiping behavior is
        // tested by test_manual_wipe.
        let data = vec![0x12, 0x34, 0x56, 0x78];
        let secure = SecureBytes::take(data);
        drop(secure); // Should wipe and not panic
    }

    #[test]
    fn test_multiple_wipes() {
        let data = vec![0xFF; 10];
        let mut secure = SecureBytes::take(data);

        secure.wipe();
        assert!(secure.data().iter().all(|&b| b == 0));

        secure.wipe();
        assert!(secure.data().iter().all(|&b| b == 0));
    }

    #[test]
    fn test_wipe_after_partial_read() {
        let data = vec![0x01, 0x02, 0x03, 0x04, 0x05];
        let mut secure = SecureBytes::take(data);

        let _first = secure.data()[0];
        let _slice = &secure.data()[1..3];

        secure.wipe();

        assert_eq!(secure.data(), &[0, 0, 0, 0, 0]);
    }

    #[test]
    fn test_large_buffer() {
        let data = vec![0xAB; 1024 * 1024]; // 1MB
        let mut secure = SecureBytes::take(data);

        assert_eq!(secure.data().len(), 1024 * 1024);

        secure.wipe();

        assert!(secure.data().iter().all(|&b| b == 0));
    }

    // BorrowedSecureBytes tests

    #[test]
    fn test_borrowed_from_and_contents() {
        let mut data = [1u8, 2, 3, 4, 5];
        let secure = BorrowedSecureBytes::from(&mut data);
        assert_eq!(secure.data(), &[1, 2, 3, 4, 5]);
    }

    #[test]
    fn test_borrowed_empty_buffer() {
        let mut data: [u8; 0] = [];
        let secure = BorrowedSecureBytes::from(&mut data);
        assert_eq!(secure.data(), &[]);
    }

    #[test]
    fn test_borrowed_manual_wipe() {
        let mut data = [0x42u8, 0x43, 0x44, 0x45];
        let mut secure = BorrowedSecureBytes::from(&mut data);

        assert_eq!(secure.data(), &[0x42, 0x43, 0x44, 0x45]);

        secure.wipe();

        assert_eq!(secure.data(), &[0, 0, 0, 0]);
    }

    #[test]
    fn test_borrowed_wipe_preserves_length() {
        let mut data = [0xAAu8; 100];
        let mut secure = BorrowedSecureBytes::from(&mut data);

        assert_eq!(secure.data().len(), 100);

        secure.wipe();

        assert_eq!(secure.data().len(), 100);
        assert!(secure.data().iter().all(|&b| b == 0));
    }

    #[test]
    fn test_borrowed_drop_wipes_buffer() {
        let mut data = [0x12u8, 0x34, 0x56, 0x78];
        {
            let _secure = BorrowedSecureBytes::from(&mut data);
        }
        // After drop, the original buffer should be wiped
        assert_eq!(data, [0, 0, 0, 0]);
    }

    #[test]
    fn test_borrowed_multiple_wipes() {
        let mut data = [0xFFu8; 10];
        let mut secure = BorrowedSecureBytes::from(&mut data);

        secure.wipe();
        assert!(secure.data().iter().all(|&b| b == 0));

        secure.wipe();
        assert!(secure.data().iter().all(|&b| b == 0));
    }

    #[test]
    fn test_borrowed_wipe_after_partial_read() {
        let mut data = [0x01u8, 0x02, 0x03, 0x04, 0x05];
        let mut secure = BorrowedSecureBytes::from(&mut data);

        let _first = secure.data()[0];
        let _slice = &secure.data()[1..3];

        secure.wipe();

        assert_eq!(secure.data(), &[0, 0, 0, 0, 0]);
    }

    #[test]
    fn test_borrowed_from_vec() {
        let mut data = vec![0xABu8; 1000];
        {
            let mut secure = BorrowedSecureBytes::from(&mut data);

            assert_eq!(secure.data().len(), 1000);

            secure.wipe();

            assert!(secure.data().iter().all(|&b| b == 0));
        }
        // After secure is dropped, we can access data again
        assert!(data.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_borrowed_original_buffer_wiped() {
        let mut data = [0xDEu8, 0xAD, 0xBE, 0xEF];
        {
            let mut secure = BorrowedSecureBytes::from(&mut data);
            secure.wipe();
        }
        // Both the wipe call and drop should have wiped it
        assert_eq!(data, [0, 0, 0, 0]);
    }
}
