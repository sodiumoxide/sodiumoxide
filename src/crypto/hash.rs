/*!
Hashing

# Security model
The `hash()` function is designed to be usable as a strong
component of DSA, RSA-PSS, key derivation, hash-based
message-authentication codes, hash-based ciphers, and various other
common applications.  "Strong" means that the security of these
applications, when instantiated with `hash()`, is the same
as the security of the applications against generic attacks. In
particular, the `hash()` function is designed to make
finding collisions difficult.

# Selected primitive
`hash()` is currently an implementation of `SHA-512`.

There has been considerable degradation of public confidence in the
security conjectures for many hash functions, including `SHA-512`.
However, for the moment, there do not appear to be alternatives that
inspire satisfactory levels of confidence. One can hope that NIST's
SHA-3 competition will improve the situation.
*/
pub use self::sha512::*;
pub mod sha512;
pub mod sha256;
