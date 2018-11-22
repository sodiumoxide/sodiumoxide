//! Rust bindings to the [sodium library](https://github.com/jedisct1/libsodium).
//!
//! Sodium is a portable implementation of Dan Bernsteins [`NaCl`: Networking and
//! Cryptography library](http://nacl.cr.yp.to).
//!
//! For details on building rust_sodium, see
//! [the README](https://github.com/maidsafe/rust_sodium/blob/master/README.md).
//!
//! For most users, if you want public-key (asymmetric) cryptography you should use
//! the functions in [`crypto::box_`](crypto/box_/index.html) for encryption/decryption.
//!
//! If you want secret-key (symmetric) cryptography you should be using the
//! functions in [`crypto::secretbox`](crypto/secretbox/index.html) for encryption/decryption.
//!
//! For public-key signatures you should use the functions in
//! [`crypto::sign`](crypto/sign/index.html) for signature creation and verification.
//!
//! Unless you know what you're doing you most certainly don't want to use the
//! functions in [`crypto::scalarmult`](crypto/scalarmult/index.html),
//! [`crypto::stream`](crypto/stream/index.html), [`crypto::auth`](crypto/auth/index.html) and
//! [`crypto::onetimeauth`](crypto/onetimeauth/index.html).
//!
//! ## Thread Safety
//! All functions in this library are thread-safe provided that the [`init()`](fn.init.html)
//! function has been called during program execution.
//!
//! If [`init()`](fn.init.html) hasn't been called then all functions except the random-number
//! generation functions and the key-generation functions are thread-safe.
//!
//! # Public-key cryptography
//!  [`crypto::box_`](crypto/box_/index.html)
//!
//!  [`crypto::sign`](crypto/sign/index.html)
//!
//! # Sealed boxes
//!  [`crypto::sealedbox`](crypto/sealedbox/index.html)
//!
//! # Secret-key cryptography
//!  [`crypto::secretbox`](crypto/secretbox/index.html)
//!
//!  [`crypto::stream`](crypto/stream/index.html)
//!
//!  [`crypto::auth`](crypto/auth/index.html)
//!
//!  [`crypto::onetimeauth`](crypto/onetimeauth/index.html)
//!
//! # Low-level functions
//!  [`crypto::hash`](crypto/hash/index.html)
//!
//!  [`crypto::verify`](crypto/verify/index.html)
//!
//!  [`crypto::shorthash`](crypto/shorthash/index.html)

#![doc(
    html_logo_url = "https://raw.githubusercontent.com/maidsafe/QA/master/Images/maidsafe_logo.png",
    html_favicon_url = "https://maidsafe.net/img/favicon.ico",
    test(attr(forbid(warnings))),
)]
// For explanation of lint checks, run `rustc -W help` or see
// https://github.com/maidsafe/QA/blob/master/Documentation/Rust%20Lint%20Checks.md
#![forbid(
    bad_style,
    exceeding_bitshifts,
    mutable_transmutes,
    no_mangle_const_items,
    unknown_crate_types,
    warnings
)]
#![deny(
    deprecated,
    improper_ctypes,
    missing_docs,
    non_shorthand_field_patterns,
    overflowing_literals,
    plugin_as_library,
    private_no_mangle_fns,
    private_no_mangle_statics,
    stable_features,
    unconditional_recursion,
    unknown_lints,
    unused,
    unused_allocation,
    unused_attributes,
    unused_comparisons,
    unused_features,
    unused_parens,
    while_true
)]
#![warn(
    trivial_numeric_casts,
    unused_extern_crates,
    unused_import_braces,
    unused_qualifications,
    unused_results
)]
// Allow `trivial_casts` to cast `u8` to `c_char`, which is `u8` or `i8`, depending on the
// architecture.
#![allow(
    box_pointers,
    missing_copy_implementations,
    missing_debug_implementations,
    trivial_casts,
    unsafe_code,
    variant_size_differences
)]
// Allow `write_literal` due to false positives. Revert this after
// https://github.com/rust-lang-nursery/rust-clippy/issues/2657 is fixed.
#![cfg_attr(feature = "cargo-clippy", allow(write_literal))]

#[cfg(test)]
extern crate hex;
extern crate libc;
extern crate rand;
#[cfg(test)]
extern crate rmp_serde;
extern crate rust_sodium_sys as ffi;
extern crate serde;
#[cfg(test)]
extern crate serde_json;
#[macro_use]
extern crate unwrap;

#[macro_use]
mod newtype_macros;
pub mod randombytes;
pub mod utils;
pub mod version;

#[cfg(test)]
mod test_utils;

/// Cryptographic functions
pub mod crypto {
    pub mod aead;
    pub mod auth;
    pub mod box_;
    pub mod hash;
    pub mod kx;
    pub mod onetimeauth;
    pub mod pwhash;
    pub mod scalarmult;
    pub mod sealedbox;
    pub mod secretbox;
    pub mod shorthash;
    pub mod sign;
    pub mod stream;
    pub mod verify;
}

/// Initialises libsodium and chooses faster versions of the primitives if possible.  Also makes the
/// random number generation functions (`gen_key`, `gen_keypair`, `gen_nonce`, `randombytes`,
/// `randombytes_into`) thread-safe.
///
/// `init()` returns `Ok` if initialisation succeeded and `Err` if it failed.
pub fn init() -> Result<(), ()> {
    if unsafe { ffi::sodium_init() } >= 0 {
        Ok(())
    } else {
        Err(())
    }
}

#[cfg_attr(feature = "cargo-clippy", allow(doc_markdown))]
/// Sets [libsodium's `randombytes_implementation`]
/// (https://download.libsodium.org/doc/advanced/custom_rng.html) to use a
/// [Rust `Rng` implementation](../rand/trait.Rng.html) and initialises libsodium.
/// See [the `rust_sodium-sys`' docs](../rust_sodium_sys/fn.init_with_rng.html) for further details.
pub fn init_with_rng<T: rand::Rng>(rng: &mut T) -> Result<(), i32> {
    ffi::init_with_rng(rng)
}
