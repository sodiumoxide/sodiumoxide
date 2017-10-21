extern crate libsodium_sys;

use libsodium_sys::*;

#[test]
fn test_crypto_verify_16_bytes() {
   assert_eq!(unsafe { crypto_verify_16_bytes() },
                       crypto_verify_16_BYTES as usize);
}

#[test]
fn test_crypto_verify_32_bytes() {
   assert_eq!(unsafe { crypto_verify_32_bytes() },
                       crypto_verify_32_BYTES as usize);
}

#[test]
fn test_crypto_verify_64_bytes() {
   assert_eq!(unsafe { crypto_verify_64_bytes() },
                       crypto_verify_64_BYTES as usize);
}
