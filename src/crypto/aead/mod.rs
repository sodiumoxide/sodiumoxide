//! This operation:
//!
//! - Encrypts a message with a key and a nonce to keep it
//!   confidential.
//! - Computes an authentication tag. This tag is used to make sure
//!   that the message, as well as optional, non-confidential
//!   (non-encrypted) data, haven't been tampered with.
//!
//! A typical use case for additional data is to store
//! protocol-specific metadata about the message, such as its length
//! and encoding.

pub mod chacha20poly1305;
