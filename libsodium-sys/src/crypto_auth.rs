// crypto_auth.h

#[test]
fn test_crypto_auth_bytes() {
    assert!(unsafe { crypto_auth_bytes() } == crypto_auth_BYTES as usize)
}

#[test]
fn test_crypto_auth_keybytes() {
    assert!(unsafe { crypto_auth_keybytes() } == crypto_auth_KEYBYTES as usize)
}

#[test]
fn test_crypto_auth_primitive() {
    unsafe {
        let s = crypto_auth_primitive();
        let s = std::ffi::CStr::from_ptr(s);
        let p = std::ffi::CStr::from_bytes_with_nul(crypto_auth_PRIMITIVE).unwrap();
        assert_eq!(s, p);
    }
}
