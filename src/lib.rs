/*!
Rust bindings to the [sodium library](https://github.com/jedisct1/libsodium). 

Sodium is a portable implementation of Dan Bernsteins [NaCl: Networking and
Cryptography library](http://nacl.cr.yp.to)

For most users, if you want public-key (asymmetric) cryptography you should use
the functions in `crypto::box` for encryption/decryption.

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
 `crypto::box`

 `crypto::sign`

# Secret-key cryptography
 `crypto::secretbox`
 
 `crypto::stream`

 `crypto::auth`

 `crypto::onetimeauth`

# Low-level functions
 `crypto::hash`

 `crypto::verify`
 */
#[link( name = "sodiumoxide"
      , package_id = "sodiumoxide"
      , vers = "0.0"
      , author = "Daniel Ashhami"
      , uuid = "28c02cec-5c30-11e3-8e0f-0021ccb4fd10")];
#[crate_type = "lib"];
//#[warn(owned_heap_memory)];
//#[warn(unstable)];
#[warn(missing_doc)];
//#[warn(heap_memory)];
#[warn(non_uppercase_statics)];
#[warn(non_camel_case_types)];
#[warn(managed_heap_memory)];
#[warn(unnecessary_qualification)];
use std::libc::c_int;

#[link(name = "sodium")]
#[link_args = "-lsodium"]
extern {
    fn sodium_init() -> c_int;
}

/**
 * `init()` initializes the sodium library and chooses faster versions of
 * the primitives if possible. `init()` also makes the random number generation
 * functions (`gen_key`, `gen_keypair`, `gen_nonce`, `randombytes`, `randombytes_into`)
 * thread-safe
 */
#[fixed_stack_segment]
pub fn init() -> bool {
    unsafe {
        sodium_init() == 0
    }
}

/**
 * Cryptographic functions
 */
pub mod crypto {
    pub mod box;
    pub mod sign;
    pub mod scalarmult; 
    pub mod auth;
    pub mod hash;
    pub mod secretbox;
    pub mod onetimeauth;
    pub mod stream;

    pub mod verify;
}

pub mod randombytes;
mod utils;
