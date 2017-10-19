extern crate libsodium_sys;

use libsodium_sys::*;

#[test]
fn test_crypto_stream_aes128ctr_keybytes() {
    assert!(unsafe { crypto_stream_aes128ctr_keybytes() } ==
            crypto_stream_aes128ctr_KEYBYTES as usize)
}

#[test]
fn test_crypto_stream_aes128ctr_noncebytes() {
    assert!(unsafe { crypto_stream_aes128ctr_noncebytes() } ==
            crypto_stream_aes128ctr_NONCEBYTES as usize)
}

#[test]
fn test_crypto_stream_aes128ctr_beforenmbytes() {
    assert!(unsafe { crypto_stream_aes128ctr_beforenmbytes() } ==
            crypto_stream_aes128ctr_BEFORENMBYTES as usize)
}
