//! The original NaCl variant of the Chacha20-Poly1305 construction,
//! an algorithm for Authenticated Encryption with Additional Data
//! (AEAD).

#[cfg(not(feature = "std"))] use prelude::*;
use ffi;
use libc::{c_ulonglong};
use std;

/// Number of bytes in `Key`.
pub const KEYBYTES: usize = ffi::crypto_aead_chacha20poly1305_KEYBYTES;

/// Number of bytes in a `Tag`.
pub const ABYTES: usize = ffi::crypto_aead_chacha20poly1305_ABYTES;

/// Number of bytes in a `Nonce`.
pub const NPUBBYTES: usize = ffi::crypto_aead_chacha20poly1305_NPUBBYTES;

new_type! {
    /// `Key` for symmetric authenticated encryption
    ///
    /// When a `Key` goes out of scope its contents
    /// will be zeroed out
    secret Key(KEYBYTES);
}

new_type! {
    /// `Nonce` for symmetric authenticated encryption
    nonce Nonce(NPUBBYTES);
}

new_type! {
    /// `Mac` for symmetric authenticated encryption
    nonce Mac(ABYTES);
}

/// Verify that the ciphertext `ciphertext` (as produced by
/// `encrypt()`) includes a valid tag using a secret key `key`, a
/// public nonce `nonce`, and additional data `ad`.
///
/// If the verification succeeds, the function puts the decrypted
/// message into `decrypted` and returns the number of bytes written
/// into `decrypted`.
///
/// # Panics
///
/// This function panics if `decrypted` is not of length at least
/// `ciphertext.len() - ABYTES`.
pub fn decrypt(decrypted: &mut [u8], ciphertext: &[u8], ad: Option<&[u8]>, nonce: &Nonce, key: &Key) -> Result<usize, ()> {
    unsafe {
        let mut mlen: c_ulonglong = decrypted.len() as c_ulonglong;
        assert!(decrypted.len() >= ciphertext.len() - ABYTES);
        let (ad_p, ad_len) = if let Some(ad) = ad {
            (ad.as_ptr(), ad.len() as c_ulonglong)
        } else {
            (std::ptr::null(), 0)
        };
        if ffi::crypto_aead_chacha20poly1305_decrypt(
            decrypted.as_mut_ptr(),
            &mut mlen,
            std::ptr::null_mut(),
            ciphertext.as_ptr(),
            ciphertext.len() as c_ulonglong,
            ad_p,
            ad_len,
            &nonce.0,
            &key.0
        ) == 0 {
            Ok(mlen as usize)
        } else {
            Err(())
        }
    }
}


/// Encrypt a message m with a key `key` and a nonce `nonce`. It puts
/// the resulting ciphertext, whose length is equal to the message,
/// into `ciphertext`.
///
/// # Panics
///
/// This function panics if `ciphertext` is not of length at least
/// `message.len() + ABYTES`.
pub fn encrypt(ciphertext: &mut [u8], message: &[u8], ad: Option<&[u8]>, nonce: &Nonce, key: &Key) -> Result<usize, ()> {
    unsafe {
        let mut clen: c_ulonglong = ciphertext.len() as c_ulonglong;
        assert!(ciphertext.len() >= message.len() + ABYTES);
        let (ad_p, ad_len) = if let Some(ad) = ad {
            (ad.as_ptr(), ad.len() as c_ulonglong)
        } else {
            (std::ptr::null(), 0)
        };
        if ffi::crypto_aead_chacha20poly1305_encrypt(
            ciphertext.as_mut_ptr(),
            &mut clen,
            message.as_ptr(),
            message.len() as c_ulonglong,
            ad_p,
            ad_len,
            std::ptr::null_mut(),
            &nonce.0,
            &key.0
        ) == 0 {
            Ok(clen as usize)
        } else {
            Err(())
        }
    }
}

/// Verify that the authentication tag `mac` is valid for the
/// ciphertext `ciphertext`, the key `key`, the nonce `nonce` and
/// optional, additional data `ad`.
///
/// If the verification succeeds, the function puts the decrypted
/// message into `decrypted`.
///
/// # Panics
///
/// This function panics if `decrypted` and `ciphertext` are of
/// different sizes.
pub fn decrypt_detached(decrypted: &mut [u8], ciphertext: &[u8], mac: &Mac, ad: Option<&[u8]>, nonce: &Nonce, key: &Key) -> Result<(), ()> {
    unsafe {
        assert!(decrypted.len() == ciphertext.len());
        let (ad_p, ad_len) = if let Some(ad) = ad {
            (ad.as_ptr(), ad.len() as c_ulonglong)
        } else {
            (std::ptr::null(), 0)
        };
        if ffi::crypto_aead_chacha20poly1305_decrypt_detached(
            decrypted.as_mut_ptr(),
            std::ptr::null_mut(),
            ciphertext.as_ptr(),
            ciphertext.len() as c_ulonglong,
            mac.0.as_ptr(),
            ad_p,
            ad_len,
            &nonce.0,
            &key.0
        ) == 0 {
            Ok(())
        } else {
            Err(())
        }
    }
}


/// Encrypt a message `message` with a key `key` and a nonce
/// `nonce`. It puts the resulting ciphertext, whose length is equal
/// to the message, into `ciphertext`.
///
/// It also computes a tag that authenticates the ciphertext as well
/// as optional, additional data `ad`. This tag is put into `mac`.
///
/// # Panics
///
/// This function panics if `message` and `ciphertext` are of
/// different sizes.
pub fn encrypt_detached(ciphertext: &mut [u8], mac: &mut Mac, message: &[u8], ad: Option<&[u8]>, nonce: &Nonce, key: &Key) -> Result<(), ()> {
    unsafe {
        assert!(ciphertext.len() == message.len());
        let (ad_p, ad_len) = if let Some(ad) = ad {
            (ad.as_ptr(), ad.len() as c_ulonglong)
        } else {
            (std::ptr::null(), 0)
        };
        let mut maclen = ABYTES as c_ulonglong;
        if ffi::crypto_aead_chacha20poly1305_encrypt_detached(
            ciphertext.as_mut_ptr(),
            mac.0.as_mut_ptr(),
            &mut maclen,
            message.as_ptr(),
            message.len() as c_ulonglong,
            ad_p,
            ad_len,
            std::ptr::null_mut(),
            &nonce.0,
            &key.0
        ) == 0 {
            Ok(())
        } else {
            Err(())
        }
    }
}
