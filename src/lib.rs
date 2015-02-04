/*!
Rust bindings to the [sodium library](https://github.com/jedisct1/libsodium).

Sodium is a portable implementation of Dan Bernsteins [NaCl: Networking and
Cryptography library](http://nacl.cr.yp.to)

For most users, if you want public-key (asymmetric) cryptography you should use
the functions in `crypto::asymmetricbox` for encryption/decryption.

If you want secret-key (symmetric) cryptography you should be using the
functions in `crypto::secretbox` for encryption/decryption.

For public-key signatures you should use the functions in `crypto::sign` for
signature creation and verification.

Unless you know what you're doing you most certainly don't want to use the
functions in `crypto::scalarmult`, `crypto::stream`, `crypto::auth` and
`crypto::onetimeauth`.

## Thread Safety
All functions in this library are thread-safe provided that the `init()`
function has been called during program execution.

If `init()` hasn't been called then all functions except the random-number
generation functions and the key-generation functions are thread-safe.

# Public-key cryptography
 `crypto::asymmetricbox`

 `crypto::sign`

# Secret-key cryptography
 `crypto::secretbox`

 `crypto::stream`

 `crypto::auth`

 `crypto::onetimeauth`

# Low-level functions
 `crypto::hash`

 `crypto::verify`

 `crypto::shorthash`
 */
#![crate_name = "sodiumoxide"]
#![crate_type = "lib"]
#![warn(missing_docs)]
#![warn(non_upper_case_globals)]
#![warn(non_camel_case_types)]
#![warn(unused_qualifications)]
#![feature(libc, collections, core)]

/* workaround: the rust compiler doesn't recognize
   the features path, test and io yet, still it warns
   about using them */
#![allow(unused_features)]
#![feature(path, test, io)]

extern crate "libsodium-sys" as ffi;
extern crate libc;

/**
 * `init()` initializes the sodium library and chooses faster versions of
 * the primitives if possible. `init()` also makes the random number generation
 * functions (`gen_key`, `gen_keypair`, `gen_nonce`, `randombytes`, `randombytes_into`)
 * thread-safe
 */
pub fn init() -> bool {
    unsafe {
        ffi::sodium_init() == 0
    }
}

#[macro_use]
mod utils;

pub mod randombytes;

/**
 * Cryptographic functions
 */
pub mod crypto {
    pub mod asymmetricbox;
    pub mod sign;
    pub mod scalarmult;
    pub mod auth;
    pub mod hash;
    pub mod secretbox;
    pub mod onetimeauth;
    pub mod stream;
    pub mod shorthash;
    pub mod verify;
}

