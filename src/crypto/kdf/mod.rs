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
//! const CONTEXT: [u8; 8] = *b"Examples";
//!
//! let key = kdf::gen_key();
//!
//! let key1 = kdf::derive_from_key(1, CONTEXT, &key);
//! let key2 = kdf::derive_from_key(2, CONTEXT, &key);
//! let key3 = kdf::derive_from_key(3, CONTEXT, &key);
//! ```

pub mod blake2b;
pub use self::blake2b::*;
