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

    aead_test_fns!({
        ::init();
        if !is_available() {
            return;
        }
    });

    struct Vector {
        key: [u8; 32],
        nonce: [u8; 12],
        message: Vec<u8>,
        ad: Vec<u8>,
        ciphertext: Vec<u8>,
        mac: Vec<u8>,
    }

    #[test]
    fn test_premade_vectors() {
        ::init();
        if !is_available() {
            return;
        }

        for v in load_vectors() {
            let k = Key(v.key);
            let n = Nonce(v.nonce);

            let mut combined = v.ciphertext.clone();
            combined.extend_from_slice(&v.mac);

            // Test encrypt
            let c_result = encrypt(&v.message, &v.ad, &n, &k);
            assert_eq!(combined, c_result);

            // Test decrypt w/ truncated ad
            for i in 0..v.mac.len() {
                let mut c_truncated_ad = v.ciphertext.clone();
                c_truncated_ad.extend_from_slice(&v.mac[0..i]);
                let m_result = decrypt(&c_truncated_ad, &v.ad, &n, &k);
                assert_eq!(Err(()), m_result);
            }

            // Test decrypt w/ truncated ciphertext
            for i in 0..v.ciphertext.len() {
                let mut c_truncated_c = Vec::new();
                c_truncated_c.extend_from_slice(&v.ciphertext[0..i]);
                c_truncated_c.extend_from_slice(&v.mac);
                let m_result = decrypt(&c_truncated_c, &v.ad, &n, &k);
                assert_eq!(Err(()), m_result);
            }

            // Finally, test normal decrypt
            let m_result = decrypt(&combined, &v.ad, &n, &k);
            assert_eq!(Ok(v.message), m_result);
        }
    }

    fn load_vectors() -> Vec<Vector> {
        use std::fs::File;
        use rustc_serialize::json::Json;

        let mut r = File::open("testvectors/aes256gcm.js").unwrap();
        let json = Json::from_reader(&mut r).unwrap();
        let json_array = json.as_array().unwrap();
        let mut result = vec![];
        for json_vec in json_array {
            let json_vec = json_vec.as_array().unwrap();

            result.push(Vector {
                key: hex_to_array32(json_vec[0].as_string().unwrap()).to_owned(),
                nonce: hex_to_array12(json_vec[1].as_string().unwrap()).to_owned(),
                message: json_vec[2].as_string().unwrap().from_hex().unwrap().to_owned(),
                ad: json_vec[3].as_string().unwrap().from_hex().unwrap().to_owned(),
                ciphertext: json_vec[4].as_string().unwrap().from_hex().unwrap().to_owned(),
                mac: json_vec[5].as_string().unwrap().from_hex().unwrap().to_owned()
            });
        }
        result
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
