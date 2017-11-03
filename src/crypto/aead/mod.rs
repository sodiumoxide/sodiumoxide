//! Authenticated Encryption with Additional Data
//! 
//! This operation:
//! 
//! * Encrypts a message with a key and a nonce to keep it confidential
//! * Computes an authentication tag. This tag is used to make sure that the
//!   message, as well as optional, non-confidential (non-encrypted) data,
//!   haven't been tampered with.
//!
//! A typical use case for additional data is to store protocol-specific
//! metadata about the message, such as its length and encoding.
//! 
//! # Supported constructions
//! 
//! Libsodium supports two popular constructions: AES256-GCM and
//! ChaCha20-Poly1305.
//! 
//! # AES256-GCM
//! 
//! The current implementation of this construction is hardware-accelerated and
//! requires the Intel SSSE3 extensions, as well as the `aesni` and `pclmul`
//! instructions.
//! 
//! Intel Westmere processors (introduced in 2010) and newer meet the
//! requirements.
//! 
//! There are no plans to support non hardware-accelerated implementations of
//! AES-GCM.
//! 
//! If portability is not a concern, AES256-GCM is the fastest option.
//! 
//! # ChaCha20-Poly1305
//! 
//! While AES is very fast on dedicated hardware, its performance on platforms
//! that lack such hardware is considerably lower. Another problem is that many
//! software AES implementations are vulnerable to cache-collision timing
//! attacks.
//! 
//! ChaCha20 is considerably faster than AES in software-only implementations,
//! making it around three times as fast on platforms that lack specialized AES
//! hardware. ChaCha20 is also not sensitive to timing attacks.
//! 
//! Poly1305 is a high-speed message authentication code.
//! 
//! The combination of the ChaCha20 stream cipher with the Poly1305
//! authenticator was proposed in January 2014 as a faster alternative to the
//! well-studied Salsa20-Poly1305 construction. ChaCha20-Poly1305 was
//! implemented in major operating systems, web browsers and crypto libraries
//! shortly after. It eventually became an official IETF standard in May 2015.
//! 
//! The ChaCha20-Poly1305 implementation in Libsodium is portable across all
//! supported architectures, and is the recommended choice for most
//! applications.

#[macro_use]
mod aead_macros;
pub mod chacha20poly1305;
pub mod aes256gcm;
