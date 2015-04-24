//! Password Hashing
//!
//! Secret keys used to encrypt or sign confidential data have to be chosen from
//! a very large keyspace. However, passwords are usually short, human-generated
//! strings, making dictionary attacks practical.
//!
//! The pwhash operation derives a secret key of any size from a password and a
//! salt.
//!
//! - The generated key has the size defined by the application, no matter what
//!   the password length is.
//! - The same password hashed with same parameters will
//!   always produce the same key.
//! - The same password hashed with different salts
//!   will produce different keys.
//! - The function deriving a key from a password
//!   and a salt is CPU intensive and intentionally requires a fair amount of
//!   memory. Therefore, it mitigates brute-force attacks by requiring a
//!   significant effort to verify each password.
//!
//! Common use cases:
//!
//! - Protecting an on-disk secret key with a password,
//! - Password storage, or rather: storing what it takes to verify a password
//!   without having to store the actual password.
pub use self::scryptsalsa208sha256::*;
pub mod scryptsalsa208sha256;
