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
    use randombytes::randombytes;

    #[test]
    fn test_encrypt_decrypt() {
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

    #[test]
    fn test_encrypt_decrypt_tamper() {
        for i in 0..256usize {
            let k = gen_key();
            let m = randombytes(i);
            let ad = [5; 10];
            let n = gen_nonce();
            let c = encrypt(&m, &ad, &n, &k);

            for i in 0..c.len() {
                let mut mangled_c = c.clone();
                mangled_c[i] = mangled_c[i] ^ 255;
                let m_new = decrypt(&mangled_c, &ad, &n, &k);
                assert_eq!(Err(()), m_new);
            }
        }
    }
}