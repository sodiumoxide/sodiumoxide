extern crate libsodium_sys;

use libsodium_sys::*;

#[test]
fn test_crypto_aead_chacha20poly1305_keybytes() {
    assert!(unsafe { crypto_aead_chacha20poly1305_keybytes() } ==
            crypto_aead_chacha20poly1305_KEYBYTES as usize)
}

#[test]
fn test_crypto_aead_chacha20poly1305_nsecbytes() {
    assert!(unsafe { crypto_aead_chacha20poly1305_nsecbytes() } ==
            crypto_aead_chacha20poly1305_NSECBYTES as usize)
}

#[test]
fn test_crypto_aead_chacha20poly1305_npubbytes() {
    assert!(unsafe { crypto_aead_chacha20poly1305_npubbytes() } ==
            crypto_aead_chacha20poly1305_NPUBBYTES as usize)
}

#[test]
fn test_crypto_aead_chacha20poly1305_abytes() {
    assert!(unsafe { crypto_aead_chacha20poly1305_abytes() } ==
            crypto_aead_chacha20poly1305_ABYTES as usize)
}
