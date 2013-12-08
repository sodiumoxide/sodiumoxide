/*!
Public-key signatures

# Security model
The `sign()` function is designed to meet the standard
notion of unforgeability for a public-key signature scheme under
chosen-message attacks.

# Selected primitive
`crypto::sign::sign` is `ed25519`, a signature scheme specified in
[Ed25519](http://ed25519.cr.yp.to/). This function is conjectured to meet the
standard notion of unforgeability for a public-key signature scheme under
chosen-message attacks.
*/
pub use self::ed25519::*;
pub mod ed25519;
pub mod edwards25519sha512batch;
