//! WARNING: Despite being the most popular AEAD construction due to its use in
//! TLS, safely using AES-GCM in a different context is tricky. No more than
//! ~ 350 GB of input data should be encrypted with a given key. This is for
//! ~ 16 KB messages - actual figures vary according to message sizes.
//! In addition, nonces are short and repeated nonces would totally destroy the
//! security of this scheme. Nonces should thus come from atomic counters,
//! which can be difficult to set up in a distributed environment.
//! Unless you absolutely need AES-GCM, use the
//! [default AEAD export](crate::crypto::aead)
//! instead - it doesn't have any of these limitations. Or, if you don't need
//! to authenticate additional data, just stick to [secretbox](crate::crypto::secretbox).
//!
//! AES primitives will not be made available unless your runtime CPU
//! is x86/x86_64 with support for the AES-NI instruction set and the CLMUL
//! instruction (Westmere and beyond).

mod aes_impl {
    use ffi::{
        crypto_aead_aes256gcm_ABYTES, crypto_aead_aes256gcm_KEYBYTES,
        crypto_aead_aes256gcm_NPUBBYTES, crypto_aead_aes256gcm_decrypt,
        crypto_aead_aes256gcm_decrypt_detached, crypto_aead_aes256gcm_encrypt,
        crypto_aead_aes256gcm_encrypt_detached,
    };

    /// `is_available` returns true if the current CPU supports aes256gcm and false otherwise.
    ///
    /// WARNING: You must call [init](crate::init) before calling this function; if you do not
    /// `is_available` will always return false even if the runtime supports aes256gcm.
    pub fn is_available() -> bool {
        unsafe { ffi::crypto_aead_aes256gcm_is_available() == 1 }
    }

    aead_module!(
        crypto_aead_aes256gcm_encrypt,
        crypto_aead_aes256gcm_decrypt,
        crypto_aead_aes256gcm_encrypt_detached,
        crypto_aead_aes256gcm_decrypt_detached,
        crypto_aead_aes256gcm_KEYBYTES as usize,
        crypto_aead_aes256gcm_NPUBBYTES as usize,
        crypto_aead_aes256gcm_ABYTES as usize,
        crate::init().is_ok() && is_available()
    );

    #[cfg(test)]
    mod test {
        use super::*;

        #[test]
        fn test_vector_1() {
            // Test vector from https://tools.ietf.org/html/rfc7714#section-16.2.2
            let m = &[
                0x47, 0x61, 0x6c, 0x6c, 0x69, 0x61, 0x20, 0x65, 0x73, 0x74, 0x20, 0x6f, 0x6d, 0x6e,
                0x69, 0x73, 0x20, 0x64, 0x69, 0x76, 0x69, 0x73, 0x61, 0x20, 0x69, 0x6e, 0x20, 0x70,
                0x61, 0x72, 0x74, 0x65, 0x73, 0x20, 0x74, 0x72, 0x65, 0x73,
            ];
            let ad = &[
                0x80, 0x40, 0xf1, 0x7b, 0x80, 0x41, 0xf8, 0xd3, 0x55, 0x01, 0xa0, 0xb2,
            ];
            let k = Key([
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
                0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
                0x1c, 0x1d, 0x1e, 0x1f,
            ]);
            let n = Nonce([
                0x51, 0x75, 0x3c, 0x65, 0x80, 0xc2, 0x72, 0x6f, 0x20, 0x71, 0x84, 0x14,
            ]);
            let c_expected = &[
                0x32, 0xb1, 0xde, 0x78, 0xa8, 0x22, 0xfe, 0x12, 0xef, 0x9f, 0x78, 0xfa, 0x33, 0x2e,
                0x33, 0xaa, 0xb1, 0x80, 0x12, 0x38, 0x9a, 0x58, 0xe2, 0xf3, 0xb5, 0x0b, 0x2a, 0x02,
                0x76, 0xff, 0xae, 0x0f, 0x1b, 0xa6, 0x37, 0x99, 0xb8, 0x7b, 0x7a, 0xa3, 0xdb, 0x36,
                0xdf, 0xff, 0xd6, 0xb0, 0xf9, 0xbb, 0x78, 0x78, 0xd7, 0xa7, 0x6c, 0x13,
            ];
            let c = seal(m, Some(ad), &n, &k);
            assert_eq!(&c[..].len(), &c_expected[..].len());
            assert_eq!(&c[0..44], &c_expected[0..44]);
        }
    }
}

mod aes_api {
    use super::aes_impl;
    use crypto::nonce::gen_random_nonce;
    #[cfg(not(feature = "std"))]
    use prelude::Vec;

    /// The Aes256Gcm struct encapsulates the crypto_aead_aes256gcm_* family of
    /// functions in a way that ensures safe usage of the API at runtime
    /// without incurring a per function call cost.
    #[derive(Debug, Clone, Copy)]
    pub struct Aes256Gcm;

    impl Aes256Gcm {
        /// Returns an `Ok` of [Aes256Gcm](self::Aes256Gcm) if the runtime
        /// supports AES and an `Err(_)` if it does not.
        ///
        /// You must call [init](crate::init) before calling this function. Failure
        /// to do so will result in `Err(_)` being returned even if the runtime
        /// hardware supports AES.
        pub fn new() -> Result<Self, ()> {
            if unsafe { ffi::crypto_aead_aes256gcm_is_available() } == 1 {
                Ok(Self)
            } else {
                Err(())
            }
        }

        /// `gen_initial_nonce` randomly generates an initial nonce
        ///
        /// WARNING: AES nonces are short enough that the probability of collision between two randomly
        /// generated nonces is nonnegligible and repeated nonce use will totally destroy the security
        /// of this scheme. Use [increment_le]( aes_impl::Nonce::increment_le) or
        /// [increment_le_inplace]( aes_impl::Nonce::increment_le_inplace) to increment a local nonce.
        /// If you are operating in a multi threaded or distributed environment you must use a shared
        /// atomic counter protocol instead.
        ///
        /// THREAD SAFETY: `gen_initial_nonce` is thread-safe provided that you have called
        /// [init](crate::init) once before using any other function from sodiumoxide.
        pub fn gen_initial_nonce(&self) -> aes_impl::Nonce {
            gen_random_nonce()
        }

        /// `gen_key()` randomly generates a secret key
        ///
        /// THREAD SAFETY: `gen_key()` is thread-safe provided that you have
        /// called `sodiumoxide::init()` once before using any other function
        /// from sodiumoxide.
        pub fn gen_key(&self) -> aes_impl::Key {
            aes_impl::gen_key()
        }

        /// `open()` verifies and decrypts a ciphertext `c` together with optional plaintext data `ad`
        /// using a secret key `k` and a nonce `n`.
        /// It returns a plaintext `Ok(m)`.
        /// If the ciphertext fails verification, `open()` returns `Err(())`.
        pub fn open(
            &self,
            c: &[u8],
            ad: Option<&[u8]>,
            n: &aes_impl::Nonce,
            k: &aes_impl::Key,
        ) -> Result<Vec<u8>, ()> {
            aes_impl::open(c, ad, n, k)
        }

        /// `open_detached()` verifies and decrypts a ciphertext `c` toghether with optional plaintext data
        /// `ad` and and authentication tag `tag`, using a secret key `k` and a nonce `n`.
        /// `c` is decrypted in place, so if this function is successful it will contain the plaintext.
        /// If the ciphertext fails verification, `open_detached()` returns `Err(())`,
        /// and the ciphertext is not modified.
        pub fn open_detached(
            &self,
            c: &mut [u8],
            ad: Option<&[u8]>,
            t: &aes_impl::Tag,
            n: &aes_impl::Nonce,
            k: &aes_impl::Key,
        ) -> Result<(), ()> {
            aes_impl::open_detached(c, ad, t, n, k)
        }

        /// `seal()` encrypts and authenticates a message `m` together with optional plaintext data `ad`
        /// using a secret key `k` and a nonce `n`. It returns a ciphertext `c`.
        pub fn seal(
            &self,
            m: &[u8],
            ad: Option<&[u8]>,
            n: &aes_impl::Nonce,
            k: &aes_impl::Key,
        ) -> Vec<u8> {
            aes_impl::seal(m, ad, n, k)
        }

        /// `seal_detached()` encrypts and authenticates a message `m` together with optional plaintext data
        /// `ad` using a secret key `k` and a nonce `n`.
        /// `m` is encrypted in place, so after this function returns it will contain the ciphertext.
        /// The detached authentication tag is returned by value.
        pub fn seal_detached(
            &self,
            m: &mut [u8],
            ad: Option<&[u8]>,
            n: &aes_impl::Nonce,
            k: &aes_impl::Key,
        ) -> aes_impl::Tag {
            aes_impl::seal_detached(m, ad, n, k)
        }
    }

    #[cfg(test)]
    mod test {
        use super::*;
        use crate::init;

        #[cfg(feature = "std")]
        #[test]
        fn test_is_available() {
            init().unwrap();
            let is_available_feat_check =
                is_x86_feature_detected!("aes") && is_x86_feature_detected!("pclmulqdq");
            assert_eq!(aes_impl::is_available(), is_available_feat_check);
        }

        #[test]
        fn test_seal_open() {
            init().unwrap();
            use randombytes::randombytes;
            let aes = Aes256Gcm::new().unwrap();
            for i in 0..256usize {
                let k = aes.gen_key();
                let n = gen_random_nonce();
                let ad = randombytes(i);
                let m = randombytes(i);
                let c = aes.seal(&m, Some(&ad), &n, &k);
                let m2 = aes.open(&c, Some(&ad), &n, &k).unwrap();
                assert_eq!(m, m2);
            }
        }

        #[test]
        fn test_seal_open_detached() {
            init().unwrap();
            use randombytes::randombytes;
            let aes = Aes256Gcm::new().unwrap();
            for i in 0..256usize {
                let k = aes.gen_key();
                let n = gen_random_nonce();
                let ad = randombytes(i);
                let mut m = randombytes(i);
                let m2 = m.clone();
                let t = aes.seal_detached(&mut m, Some(&ad), &n, &k);
                aes.open_detached(&mut m, Some(&ad), &t, &n, &k).unwrap();
                assert_eq!(m, m2);
            }
        }
    }
}

pub use self::aes_api::Aes256Gcm;
pub use self::aes_impl::{is_available, Key, Nonce, Tag, KEYBYTES, NONCEBYTES, TAGBYTES};
