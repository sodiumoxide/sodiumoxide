//! Libsodium Base64 encoding/decoding helper functions
use ffi;
#[cfg(not(feature = "std"))]
use prelude::*;
use std::ptr;

// size_t
// crypto_vrf_publickeybytes(void)
// {
//     return crypto_vrf_PUBLICKEYBYTES;
// }

pub fn vrf_publickeybytes() -> () {}
