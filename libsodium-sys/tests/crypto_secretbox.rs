extern crate libsodium_sys;

use libsodium_sys::*;

#[test]
fn test_crypto_secretbox_keybytes() {
    assert!(unsafe {
        crypto_secretbox_keybytes()
    } == crypto_secretbox_KEYBYTES as usize)
}

#[test]
fn test_crypto_secretbox_noncebytes() {
    assert!(unsafe {
        crypto_secretbox_noncebytes()
    } == crypto_secretbox_NONCEBYTES as usize)
}

#[test]
fn test_crypto_secretbox_macbytes() {
    assert!(unsafe {
        crypto_secretbox_macbytes()
    } == crypto_secretbox_MACBYTES as usize)
}

#[test]
fn test_crypto_secretbox_primitive() {
    unsafe {
        let s = crypto_secretbox_primitive();
        let s = std::ffi::CStr::from_ptr(s);
        let b = std::ffi::CStr::from_bytes_with_nul(crypto_secretbox_PRIMITIVE).unwrap();
        assert_eq!(s, b);
    }
}
