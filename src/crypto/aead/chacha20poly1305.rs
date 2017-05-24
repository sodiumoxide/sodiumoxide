//! The original ChaCha20-Poly1305 construction
//! 
//! The original ChaCha20-Poly1305 construction can safely encrypt up to 2^64
//! messages with the same key, without any practical limit to the size of a
//! message (up to 2^70 bytes).
//!
//! # Example
//! 
//! ```
//! use sodiumoxide::crypto::aead::chacha20poly1305 as aead;
//! use sodiumoxide;
//!
//! sodiumoxide::init();
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
use ffi;

aead_module!(
    ffi::crypto_aead_chacha20poly1305_encrypt,
    ffi::crypto_aead_chacha20poly1305_decrypt,
    ffi::crypto_aead_chacha20poly1305_KEYBYTES,
    ffi::crypto_aead_chacha20poly1305_NPUBBYTES,
    ffi::crypto_aead_chacha20poly1305_ABYTES);


#[cfg(test)]
mod test {
    use super::*;

    aead_test_fns!(());

    #[test]
    fn test_canned_vector() {
        let k = Key([
            0x42, 0x90, 0xbc, 0xb1, 0x54, 0x17, 0x35, 0x31, 0xf3, 0x14, 0xaf,
            0x57, 0xf3, 0xbe, 0x3b, 0x50, 0x06, 0xda, 0x37, 0x1e, 0xce, 0x27,
            0x2a, 0xfa, 0x1b, 0x5d, 0xbd, 0xd1, 0x10, 0x0a, 0x10, 0x07]);
        let m = vec![0x86, 0xd0, 0x99, 0x74, 0x84, 0x0b, 0xde, 0xd2, 0xa5, 0xca];
        let n = Nonce([0xcd, 0x7c, 0xf6, 0x7b, 0xe3, 0x9c, 0x79, 0x4a]);
        let ad = vec![0x87, 0xe2, 0x29, 0xd4, 0x50, 0x08, 0x45, 0xa0, 0x79, 0xc0];

        let c = encrypt(&m, &ad, &n, &k);

        for i in 0..c.len() {
            let mut mangled_c = c.clone();
            mangled_c[i] = mangled_c[i] + 1;
            let m_new = decrypt(&mangled_c, &ad, &n, &k);
            assert_eq!(Err(()), m_new);
        }

    }
}
