//! Public-key signatures
//!
//! # Security model
//! The `sign()` function is designed to meet the standard
//! notion of unforgeability for a public-key signature scheme under
//! chosen-message attacks.
//!
//! # Selected primitive
//! `crypto::sign::sign` is `ed25519`, a signature scheme specified in
//! [Ed25519](http://ed25519.cr.yp.to/). This function is conjectured to meet the
//! standard notion of unforgeability for a public-key signature scheme under
//! chosen-message attacks.
//!
//! # Alternate primitives
//!
//! --------------------------------------------------------------------------------
//! |crypto_sign                         | PUBLICKEYBYTES | SECRETKEYBYTES | BYTES |
//! |------------------------------------|----------------|----------------|-------|
//! |crypto_sign_ed25519                 | 32             | 64             | 64    |
//! |crypto_sign_edwards25519sha512batch | 32             | 64             | 64    |
//! --------------------------------------------------------------------------------
//!
//! crypto_sign_edwards25519sha512batch is a prototype. It has been replaced with
//! Ed25519 and is only kept here for compatibility reasons.
pub use self::ed25519::*;
pub mod ed25519;
pub mod edwards25519sha512batch;
