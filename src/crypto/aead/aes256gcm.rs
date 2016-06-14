//! Authenticated Encryption with Additional Data using AES-GCM
//! 
//! # Example (combined mode)
//! 
//! ```
//! use sodiumoxide;
//! use sodiumoxide::crypto::aead::aes256gcm as aead;
//!
//! sodiumoxide::init();
//! if !aead::is_available() {
//!     // panic if this is unexpected, or fall back
//!     // to chacha20poly1305
//!    panic!();
//! }
//!
//! let key = aead::gen_key();
//! let nonce = aead::gen_nonce();
//! let plaintext = b"some data";
//! let additional_data = b"extra authenticated data";
//! let ciphertext = aead::encrypt(plaintext, additional_data, &nonce, &key);
//! let their_plaintext = aead::decrypt(&ciphertext, additional_data,
//!                                     &nonce, &key).unwrap();
//! assert!(plaintext == &their_plaintext[..]);
//! ```
//!
//! # Purpose
//! 
//! This operation:
//!
//! * Encrypts a message with a key and a nonce to keep it confidential
//! * Computes an authentication tag. This tag is used to make sure that the
//!   message, as well as optional, non-confidential (non-encrypted) data,
//!   haven't been tampered with.
//!
//! A typical use case for additional data is to store protocol-specific
//! metadata about the message, such as its length and encoding.
//!
//! It can also be used as a MAC, with an empty message.
//! 
//! Decryption will never be performed, even partially, before verification.
//!
//! When supported by the CPU, AES-GCM is the fastest AEAD cipher available in
//! this library.
//!
//! # Limitations
//! 
//! The current implementation of this construction is hardware-accelerated and
//! requires the Intel SSSE3 extensions, as well as the `aesni` and `pclmul`
//! instructions.
//! 
//! Intel Westmere processors (introduced in 2010) and newer meet the
//! requirements.
//! 
//! There are no plans to support non hardware-accelerated implementations of
//! AES-GCM. If portability is a concern, use ChaCha20-Poly1305 instead.
//!
//! Before using the functions below, hardware support for AES can be checked
//! with `is_available()`. The library must have been initialized with
//! `sodiumoxide::init()` prior to calling this function.

use ffi;

aead_module!(
    ffi::crypto_aead_aes256gcm_encrypt,
    ffi::crypto_aead_aes256gcm_decrypt,
    ffi::crypto_aead_aes256gcm_KEYBYTES,
    ffi::crypto_aead_aes256gcm_NPUBBYTES,
    ffi::crypto_aead_aes256gcm_ABYTES);


/// `is_available()` true if aes256gcm crypto support is available on this
/// machine
///
/// You must call sodiumoxide::init() prior to calling this function.
///
/// AES-GCM is only supported on machines with aesni hardware acceleration
/// support. If you need a broadly available AEAD, use ChaCha20-Poly1305
/// instead.
pub fn is_available() -> bool {
    unsafe {
        ffi::crypto_aead_aes256gcm_is_available() == 1
    }
}


#[cfg(test)]
mod test {
    use super::*;
    use rustc_serialize::hex::FromHex;
    use randombytes::randombytes;
    
    #[test]
    fn test_encrypt_decrypt() {
        ::init();
        if !is_available() {
            return;
        }

        // Vary input length
        for i in 0..256usize {
            let k = gen_key();
            let m = randombytes(i);
            let ad = [5; 10];
            let n = gen_nonce();

            let c = encrypt(&m, &ad, &n, &k);
            let m_new = decrypt(&c, &ad, &n, &k);
            assert_eq!(m, m_new.unwrap());
        }

        // Vary ad length
        for i in 0..256usize {
            let k = gen_key();
            let m = randombytes(10);
            let ad = vec![5; i];
            let n = gen_nonce();
            let c = encrypt(&m, &ad, &n, &k);
            let m_new = decrypt(&c, &ad, &n, &k);
            assert_eq!(m, m_new.unwrap());
        }
    }

    struct Vector {
        key_hex: & 'static str,
        nonce_hex: & 'static str,
        message_hex: & 'static str,
        ad_hex: & 'static str,
        ciphertext_hex: & 'static str,
        mac_hex: & 'static str,
    }

    const VECTORS : [Vector; 3] = [
        Vector{
            key_hex: "b52c505a37d78eda5dd34f20c22540ea1b58963cf8e5bf8ffa85f9f2492505b4",
            nonce_hex: "516c33929df5a3284ff463d7",
            message_hex: "",
            ad_hex: "",
            ciphertext_hex: "",
            mac_hex: "bdc1ac884d332457a1d2664f168c76f0"
        },
        Vector{
            key_hex: "381873b5f9579d8241f0c61f0d9e327bb9f678691714aaa48ea7d92678d43fe7",
            nonce_hex: "3fc8bec23603158e012d65e5",
            message_hex: "7b622e9b408fe91f6fa800ecef838d36",
            ad_hex: "",
            ciphertext_hex: "8ca4de5b4e2ab22431a009f3ddd01bae",
            mac_hex: "b3a7f80e3edf322622731550164cd747",
        },
        Vector{
            key_hex: "92e11dcdaa866f5ce790fd24501f92509aacf4cb8b1339d50c9c1240935dd08b",
            nonce_hex: "ac93a1a6145299bde902f21a",
            message_hex: "2d71bcfa914e4ac045b2aa60955fad24",
            ad_hex: "1e0889016f67601c8ebea4943bc23ad6",
            ciphertext_hex: "8995ae2e6df3dbf96fac7b7137bae67f",
            mac_hex: "eca5aa77d51d4a0a14d9c51e1da474ab",
        },
    ];

    #[test]
    fn test_premade_vectors() {
        ::init();
        if !is_available() {
            return;
        }

        for vector in VECTORS.iter() {
            let k = Key(hex_to_array32(vector.key_hex));
            let n = Nonce(hex_to_array12(vector.nonce_hex));
            let m = vector.message_hex.from_hex().unwrap();
            let ad = vector.ad_hex.from_hex().unwrap();
            let c = vector.ciphertext_hex.from_hex().unwrap();
            let mac = vector.mac_hex.from_hex().unwrap();

            let mut combined = c.clone();
            combined.append(&mut mac.to_owned());

            let c_test = encrypt(&m, &ad, &n, &k);
            assert_eq!(combined, c_test);
            let m_test = decrypt(&c_test, &ad, &n, &k).unwrap();
            assert_eq!(m, m_test);
        }
    }

    #[test]
    fn test_premade_vectors_tamper() {
        ::init();
        if !is_available() {
            return;
        }

        for vector in VECTORS.iter() {
            let k = Key(hex_to_array32(vector.key_hex));
            let n = Nonce(hex_to_array12(vector.nonce_hex));
            let ad = vector.ad_hex.from_hex().unwrap();
            let c = vector.ciphertext_hex.from_hex().unwrap();
            let mac = vector.mac_hex.from_hex().unwrap();

            for i in 0..(c.len() + mac.len()) {
                let mut combined = c.clone();
                combined.append(&mut mac.to_owned());

                combined[i] = combined[i] ^ 255;

                let m_test = decrypt(&combined, &ad, &n, &k);
                assert_eq!(Err(()), m_test);
            }
        }
    }


    fn hex_to_array32(hex: &str) -> [u8; 32] {
        let bytes = hex.from_hex().unwrap();
        let mut result = [0u8; 32];
        for i in 0..32 {
            result[i] = bytes[i];
        }
        result
    }

    fn hex_to_array12(hex: &str) -> [u8; 12] {
        let bytes = hex.from_hex().unwrap();
        let mut result = [0u8; 12];
        for i in 0..12 {
            result[i] = bytes[i];
        }
        result
    }

}
