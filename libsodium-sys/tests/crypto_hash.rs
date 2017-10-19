extern crate libsodium_sys;

use libsodium_sys::*;

#[test]
fn test_crypto_hash_bytes() {
    assert!(unsafe { crypto_hash_bytes() } == crypto_hash_BYTES as usize)
}

#[test]
fn test_crypto_hash_primitive() {
    unsafe {
        let s = crypto_hash_primitive();
        let s = std::ffi::CStr::from_ptr(s);
        let b = std::ffi::CStr::from_bytes_with_nul(crypto_hash_PRIMITIVE).unwrap();
        assert_eq!(s, b);
    }
}
