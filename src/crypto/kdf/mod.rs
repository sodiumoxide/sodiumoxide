//! Key derivation
//!
//! Multiple secret subkeys can be derived from a single master key. Given the master key and a key
//! identifier, a subkey can be deterministically computed. However, given a subkey, an attacker
//! cannot compute the master key nor any other subkeys.
//!
//! This API was introduced in libsodium 1.0.12
//!
//! # Example
//!
//! ```
//! use sodiumoxide::crypto::kdf;
//!
//! let key = kdf::gen_key();
//! let context = kdf::Context::from_slice(&[0u8; 8]).unwrap();
//!
//! let key1 = kdf::derive_from_key(1, &context, &key);
//! let key2 = kdf::derive_from_key(2, &context, &key);
//! let key3 = kdf::derive_from_key(3, &context, &key);
//! ```

pub mod blake2b;
pub use self::blake2b::*;
