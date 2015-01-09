/*!
Secret-key encryption

# Security Model
The `stream()` function, viewed as a function of the nonce for a
uniform random key, is designed to meet the standard notion of
unpredictability ("PRF"). For a formal definition see, e.g., Section 2.3
of Bellare, Kilian, and Rogaway, "The security of the cipher block
chaining message authentication code," Journal of Computer and System
Sciences 61 (2000), 362–399;
http://www-cse.ucsd.edu/~mihir/papers/cbc.html.

This means that an attacker cannot distinguish this function from a
uniform random function. Consequently, if a series of messages is
encrypted by `stream_xor()` with a different nonce for each message,
the ciphertexts are indistinguishable from uniform random strings of the
same length.

Note that the length is not hidden. Note also that it is the caller's
responsibility to ensure the uniqueness of nonces—for example, by using
nonce 1 for the first message, nonce 2 for the second message, etc.
Nonces are long enough that randomly generated nonces have negligible
risk of collision.

NaCl does not make any promises regarding the resistance of `stream()` to
"related-key attacks." It is the caller's responsibility to use proper
key-derivation functions.

# Selected primitive
`stream()` is `crypto_stream_xsalsa20`, a particular cipher specified in
[Cryptography in NaCl](http://nacl.cr.yp.to/valid.html), Section 7.
This cipher is conjectured to meet the standard notion of
unpredictability.

# Alternate primitives
NaCl supports the following secret-key encryption functions:

------------------------------------------------------------
|crypto_stream           |primitive   |KEYBYTES |NONCEBYTES|
|------------------------|------------|---------|----------|
|crypto_stream_aes128ctr |AES-128-CTR |16       |16        |
|crypto_stream_salsa208  |Salsa20/8   |32       |8         |
|crypto_stream_salsa2012 |Salsa20/12  |32       |8         |
|crypto_stream_salsa20   |Salsa20/20  |32       |8         |
|crypto_stream_xsalsa20  |XSalsa20/20 |32       |24        |
------------------------------------------------------------

Beware that several of these primitives have 8-byte nonces. For those
primitives it is no longer true that randomly generated nonces have negligible
risk of collision. Callers who are unable to count 1, 2, 3..., and who insist
on using these primitives, are advised to use a randomly derived key for each
message.

*/
pub use self::xsalsa20::*;
#[path="stream_macros.rs"]
#[macro_use]
mod stream_macros;
#[path="xsalsa20.rs"]
pub mod xsalsa20;
#[path="aes128ctr.rs"]
pub mod aes128ctr;
#[path="salsa208.rs"]
pub mod salsa208;
#[path="salsa2012.rs"]
pub mod salsa2012;
#[path="salsa20.rs"]
pub mod salsa20;
