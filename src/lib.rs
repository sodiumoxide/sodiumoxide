//! Rust bindings to the [sodium library](https://github.com/jedisct1/libsodium).
//!
//! Sodium is a portable implementation of Dan Bernsteins [NaCl: Networking and
//! Cryptography library](http://nacl.cr.yp.to)
//!
//! For most users, if you want public-key (asymmetric) cryptography you should use
//! the functions in `crypto::box_` for encryption/decryption.
//!
//! If you want secret-key (symmetric) cryptography you should be using the
//! functions in `crypto::secretbox` for encryption/decryption.
//!
//! For public-key signatures you should use the functions in `crypto::sign` for
//! signature creation and verification.
//!
//! Unless you know what you're doing you most certainly don't want to use the
//! functions in `crypto::scalarmult`, `crypto::stream`, `crypto::auth` and
//! `crypto::onetimeauth`.
//!
//! # Thread Safety
//! All functions in this library are thread-safe provided that the
//! [`init()`](fn.init.html) function has been called during program execution.
//! `init()` itself is thread-safe, although it will only report success a
//! maximum of once.
//!
//! If `init()` hasn't been called then all functions except the random-number
//! generation functions and the key-generation functions are thread-safe.
//!
//! # Public-key cryptography
//!  `crypto::box_`
//!
//!  `crypto::sign`
//!
//! # Secret-key cryptography
//!  `crypto::secretbox`
//!
//!  `crypto::stream`
//!
//!  `crypto::auth`
//!
//!  `crypto::onetimeauth`
//!
//! # Low-level functions
//!  `crypto::hash`
//!
//!  `crypto::verify`
//!
//!  `crypto::shorthash`
#![crate_name = "sodiumoxide"]
#![crate_type = "lib"]
#![warn(missing_docs)]
#![warn(non_upper_case_globals)]
#![warn(non_camel_case_types)]
#![warn(unused_qualifications)]

extern crate libsodium_sys as ffi;
extern crate libc;
extern crate rustc_serialize;

/// `init()` initializes the sodium library and chooses faster versions of
/// the primitives if possible. `init()` also makes the random number generation
/// functions (`gen_key`, `gen_keypair`, `gen_nonce`, `gen_salt`, `randombytes`,
/// `randombytes_into`) thread-safe.
///
/// It is safe to call this function multiple times even concurrently from
/// different threads. It will return `true` the first time the initialization
/// succeeds, otherwise it will return `false`.
pub fn init() -> bool {
    use std::sync::{Once, ONCE_INIT};
    use std::sync::atomic::{AtomicBool, Ordering};

    let ran_init = AtomicBool::new(false);
    static INIT: Once = ONCE_INIT;
    INIT.call_once(|| {
        let init_result = unsafe {
            ffi::sodium_init() == 0
        };
        ran_init.store(init_result, Ordering::Relaxed);
    });
    ran_init.load(Ordering::Relaxed)
}

mod marshal;
#[macro_use]
mod newtype_macros;
pub mod randombytes;
pub mod utils;

#[cfg(test)]
mod test_utils;

/// Cryptographic functions
pub mod crypto {
    pub mod box_;
    pub mod sign;
    pub mod scalarmult;
    pub mod auth;
    pub mod hash;
    pub mod secretbox;
    pub mod onetimeauth;
    pub mod pwhash;
    pub mod stream;
    pub mod shorthash;
    pub mod verify;
}

#[cfg(test)]
mod test {
    #[test]
    fn test_init() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::thread;

        let thread_count = 16;
        let init_success_count = Arc::new(AtomicUsize::new(0));
        let mut threads = vec![];

        for _ in 0..thread_count {
            let local_count = init_success_count.clone();
            threads.push(thread::spawn(move || {
                if super::init() {
                    let _ = local_count.fetch_add(1, Ordering::SeqCst);
                }
            }));
        }

        for thread_handle in threads {
            let _ = thread_handle.join();
        }

        assert!(init_success_count.load(Ordering::SeqCst) <= 1);
    }
}
