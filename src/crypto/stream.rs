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
*/
pub use self::xsalsa20::*;
pub mod xsalsa20;
