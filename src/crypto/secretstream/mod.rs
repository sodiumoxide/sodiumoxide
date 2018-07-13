//! Stream encryption/file encryption
//!
//! This high-level API encrypts a sequence of messages, or a single message split into an arbitrary
//! number of chunks, using a secret key, with the following properties:
//!
//! * Messages cannot be truncated, removed, reordered, duplicated or modified without this being
//!   detected by the decryption functions.
//! * The same sequence encrypted twice will produce different ciphertexts.
//! * An authentication tag is added to each encrypted message: stream corruption will be detected
//!   early, without having to read the stream until the end.
//! * Each message can include additional data (ex: timestamp, protocol version) in the computation
//!   of the authentication tag.
//! * Messages can have different sizes.
//! * There are no practical limits to the total length of the stream,
//!   or to the total number of individual messages.
//! * Ratcheting: at any point in the stream, it is possible to "forget" the key used to encrypt
//!   the previous messages, and switch to a new key.
//!
//! This API can be used to securely send an ordered sequence of messages to a peer.
//! Since the length of the stream is not limited, it can also be used to encrypt files
//! regardless of their size.
//!
//! It transparently generates nonces and automatically handles key rotation.
//!
//! The crypto_secretstream_*() API was introduced in libsodium 1.0.14.
//!
//! # Example (encryption)
//! ```
//! use sodiumoxide::crypto::secretstream;
//!
//! let msg1 = "some message 1";
//! let msg2 = "other message";
//! let msg3 = "final message";
//!
//! // initialize encrypt secret stream
//! let (mut enc_stream, header, key) = secretstream::Encryptor::new().unwrap();
//!
//! // encrypt first message, tagging it as message.
//! let ciphertext1 = enc_stream.aencrypt_message(msg1.as_bytes(), None).unwrap();
//!
//! // encrypt second message, tagging it as push.
//! let ciphertext2 = enc_stream.aencrypt_push(msg2.as_bytes(), None).unwrap();
//!
//! // encrypt third message, tagging it as final.
//! let ciphertext3 = enc_stream.aencrypt_finalize(msg3.as_bytes(), None).unwrap();
//!
//! // initialize decrypt secret stream
//! let mut dec_stream = secretstream::Decryptor::init(&header, &key).unwrap();
//!
//! // decrypt first message.
//! assert!(!dec_stream.is_finalized());
//! let (decrypted1, tag1) = dec_stream.vdecrypt(&ciphertext1, None).unwrap();
//! assert_eq!(tag1, secretstream::Tag::Message);
//! assert_eq!(msg1.as_bytes(), &decrypted1[..]);
//!
//! // decrypt second message.
//! assert!(!dec_stream.is_finalized());
//! let (decrypted2, tag2) = dec_stream.vdecrypt(&ciphertext2, None).unwrap();
//! assert_eq!(tag2, secretstream::Tag::Push);
//! assert_eq!(msg2.as_bytes(), &decrypted2[..]);
//!
//! // decrypt last message.
//! assert!(!dec_stream.is_finalized());
//! let (decrypted3, tag3) = dec_stream.vdecrypt(&ciphertext3, None).unwrap();
//! assert_eq!(tag3, secretstream::Tag::Final);
//! assert_eq!(msg3.as_bytes(), &decrypted3[..]);
//!
//! // dec_stream is now finalized.
//! assert!(dec_stream.is_finalized());
//!
//! ```
pub use self::xchacha20poly1305::*;
#[macro_use]
mod secretstream_macros;
pub mod xchacha20poly1305;
