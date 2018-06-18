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
//! # Example (stream encryption)
//! ```
//! use sodiumoxide::crypto::stream;
//!
//! let key = stream::gen_key();
//! let nonce = stream::gen_nonce();
//! let keystream = stream::stream(128, &nonce, &key); // generate 128 bytes of keystream
//! ```
//!
//! # Example (encryption)
//! ```
//! use sodiumoxide::crypto::secretstream;
//!
//! let key = secretstream::gen_key();
//!
//! let msg1 = "some message 1";
//! let msg2 = "other message";
//! let msg3 = "final message";
//!
//! // initialize encrypt secret stream
//! let (mut enc_stream, header) = secretstream::init_push(&key);
//!
//! // encrypt first message, tagging it as message.
//! let cyphertext1 = enc_stream.push(msg1.as_bytes(), None, secretstream::TAG_MESSAGE);
//!
//! // encrypt second message, tagging it as message.
//! let cyphertext2 = enc_stream.push(msg2.as_bytes(), None, secretstream::TAG_MESSAGE);
//!
//! // encrypt third message, tagging it as final.
//! let cyphertext3 = enc_stream.push(msg3.as_bytes(), None, secretstream::TAG_FINAL);
//!
//! // initialize decrypt secret stream
//! let mut dec_stream = secretstream::init_pull(&header, &key).unwrap();
//!
//! // decrypt first message.
//! let (decrypted1, tag1) = dec_stream.pull(&cyphertext1, None).unwrap();
//! assert_eq!(tag1, secretstream::TAG_MESSAGE);
//! assert_eq!(msg1.as_bytes(), &decrypted1[..]);
//!
//! // decrypt second message.
//! let (decrypted2, tag2) = dec_stream.pull(&cyphertext2, None).unwrap();
//! assert_eq!(tag2, secretstream::TAG_MESSAGE);
//! assert_eq!(msg2.as_bytes(), &decrypted2[..]);
//!
//! // decrypt last message.
//! let (decrypted3, tag3) = dec_stream.pull(&cyphertext3, None).unwrap();
//! assert_eq!(tag3, secretstream::TAG_FINAL);
//! assert_eq!(msg3.as_bytes(), &decrypted3[..]);
//!
//! ```
pub use self::xchacha20poly1305::*;
#[macro_use]
mod secretstream_macros;
pub mod xchacha20poly1305;
