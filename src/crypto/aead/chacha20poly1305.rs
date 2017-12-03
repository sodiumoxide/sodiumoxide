//! The original variant of the Chacha20-Poly1305 construction, an
//! algorithm for Authenticated Encryption with Additional Data
//! (AEAD).

#[cfg(not(feature = "std"))] use prelude::*;
use ffi;
use libc::{c_ulonglong};
pub use crypto::stream::chacha20::{Key, Nonce, KEYBYTES, NONCEBYTES};

/// Number of bytes in a `Tag`.
pub const ABYTES: usize = ffi::crypto_aead_chacha20poly1305_ABYTES;

new_type! {
    /// `Mac` for symmetric authenticated encryption
    public Mac(ABYTES);
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
            (0 as *const u8, 0)
        };
        if ffi::crypto_aead_chacha20poly1305_decrypt(
            decrypted.as_mut_ptr(),
            &mut mlen,
            0 as *mut _,
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

/// Same as `decrypt`, but modifies the message in place instead of
/// requiring a different slice for the output (in particular, this
/// function does not panic).
pub fn decrypt_in_place(ciphertext: &mut [u8], ad: Option<&[u8]>, nonce: &Nonce, key: &Key) -> Result<usize, ()> {
    unsafe {
        let mut mlen: c_ulonglong = ciphertext.len() as c_ulonglong;
        let (ad_p, ad_len) = if let Some(ad) = ad {
            (ad.as_ptr(), ad.len() as c_ulonglong)
        } else {
            (0 as *const u8, 0)
        };
        if ffi::crypto_aead_chacha20poly1305_decrypt(
            ciphertext.as_mut_ptr(),
            &mut mlen,
            0 as *mut _,
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
pub fn encrypt(ciphertext: &mut [u8], message: &[u8], ad: Option<&[u8]>, nonce: &Nonce, key: &Key) -> usize {
    unsafe {
        let mut clen: c_ulonglong = ciphertext.len() as c_ulonglong;
        assert!(ciphertext.len() >= message.len() + ABYTES);
        let (ad_p, ad_len) = if let Some(ad) = ad {
            (ad.as_ptr(), ad.len() as c_ulonglong)
        } else {
            (0 as *const u8, 0)
        };
        ffi::crypto_aead_chacha20poly1305_encrypt(
            ciphertext.as_mut_ptr(),
            &mut clen,
            message.as_ptr(),
            message.len() as c_ulonglong,
            ad_p,
            ad_len,
            0 as *mut _,
            &nonce.0,
            &key.0
        );
        clen as usize
    }
}

/// Same as `encrypt`, but modifies the message in place instead of
/// requiring a different slice for the output (in particular, this
/// function does not panic).
pub fn encrypt_in_place(message: &mut [u8], ad: Option<&[u8]>, nonce: &Nonce, key: &Key) -> usize {
    unsafe {
        let mut clen: c_ulonglong = message.len() as c_ulonglong;
        let (ad_p, ad_len) = if let Some(ad) = ad {
            (ad.as_ptr(), ad.len() as c_ulonglong)
        } else {
            (0 as *const u8, 0)
        };
        ffi::crypto_aead_chacha20poly1305_encrypt(
            message.as_mut_ptr(),
            &mut clen,
            message.as_ptr(),
            message.len() as c_ulonglong,
            ad_p,
            ad_len,
            0 as *mut _,
            &nonce.0,
            &key.0
        );
        clen as usize
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
            (0 as *const u8, 0)
        };
        if ffi::crypto_aead_chacha20poly1305_decrypt_detached(
            decrypted.as_mut_ptr(),
            0 as *mut _,
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

/// Same as `decrypt_detached`, but modifies the message in place
/// instead of requiring a different slice for the output.
pub fn decrypt_detached_in_place(ciphertext: &mut [u8], mac: &Mac, ad: Option<&[u8]>, nonce: &Nonce, key: &Key) -> Result<(), ()> {
    unsafe {
        let (ad_p, ad_len) = if let Some(ad) = ad {
            (ad.as_ptr(), ad.len() as c_ulonglong)
        } else {
            (0 as *const u8, 0)
        };
        if ffi::crypto_aead_chacha20poly1305_decrypt_detached(
            ciphertext.as_mut_ptr(),
            0 as *mut _,
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
pub fn encrypt_detached(ciphertext: &mut [u8], mac: &mut Mac, message: &[u8], ad: Option<&[u8]>, nonce: &Nonce, key: &Key) {
    unsafe {
        assert!(ciphertext.len() == message.len());
        let (ad_p, ad_len) = if let Some(ad) = ad {
            (ad.as_ptr(), ad.len() as c_ulonglong)
        } else {
            (0 as *const u8, 0)
        };
        let mut maclen = ABYTES as c_ulonglong;
        ffi::crypto_aead_chacha20poly1305_encrypt_detached(
            ciphertext.as_mut_ptr(),
            mac.0.as_mut_ptr(),
            &mut maclen,
            message.as_ptr(),
            message.len() as c_ulonglong,
            ad_p,
            ad_len,
            0 as *mut _,
            &nonce.0,
            &key.0
        );
    }
}

/// Same as `encrypt_detached`, but modifies the message in place
/// instead of requiring a different slice for the output.
pub fn encrypt_detached_in_place(message: &mut [u8], mac: &mut Mac, ad: Option<&[u8]>, nonce: &Nonce, key: &Key) {
    unsafe {
        let (ad_p, ad_len) = if let Some(ad) = ad {
            (ad.as_ptr(), ad.len() as c_ulonglong)
        } else {
            (0 as *const u8, 0)
        };
        let mut maclen = ABYTES as c_ulonglong;
        ffi::crypto_aead_chacha20poly1305_encrypt_detached(
            message.as_mut_ptr(),
            mac.0.as_mut_ptr(),
            &mut maclen,
            message.as_ptr(),
            message.len() as c_ulonglong,
            ad_p,
            ad_len,
            0 as *mut _,
            &nonce.0,
            &key.0
        );
    }
}

#[cfg(test)]
mod test {
    use super::*;

    // Test from https://tools.ietf.org/html/draft-agl-tls-chacha20poly1305-04#section-7
    #[test]
    fn test_seal_open() {
        let plaintext = &[0x86,0xd0,0x99,0x74,0x84,0x0b,0xde,0xd2,0xa5,0xca];
        let key = Key([0x42,0x90,0xbc,0xb1,0x54,0x17,0x35,0x31,
                       0xf3,0x14,0xaf,0x57,0xf3,0xbe,0x3b,0x50,
                       0x06,0xda,0x37,0x1e,0xce,0x27,0x2a,0xfa,
                       0x1b,0x5d,0xbd,0xd1,0x10,0x0a,0x10,0x07]);
        let nonce = Nonce([0xcd,0x7c,0xf6,0x7b,0xe3,0x9c,0x79,0x4a]);
        let aad = &[0x87,0xe2,0x29,0xd4,0x50,0x08,0x45,0xa0,0x79,0xc0];

        let output = &[0xe3,0xe4,0x46,0xf7,0xed,0xe9,0xa1,0x9b,
                       0x62,0xa4,0x67,0x7d,0xab,0xf4,0xe3,0xd2,
                       0x4b,0x87,0x6b,0xb2,0x84,0x75,0x38,0x96,
                       0xe1,0xd6];


        let mut ciphertext = vec![0; output.len()];
        let n = encrypt(&mut ciphertext, plaintext, Some(aad), &nonce, &key);
        assert_eq!(n, output.len());
        assert_eq!(&ciphertext[..], output);
    }
}
