// crypto_auth.h

#[test]
fn test_crypto_auth_bytes() {
    assert!(unsafe { crypto_auth_bytes() as usize } == crypto_auth_BYTES)
}

#[test]
fn test_crypto_auth_keybytes() {
    assert!(unsafe { crypto_auth_keybytes() as usize } == crypto_auth_KEYBYTES)
}

#[test]
fn test_crypto_auth_primitive() {
    unsafe {
        let s = crypto_auth_primitive();
        let s = std::ffi::CStr::from_ptr(s).to_bytes();
        assert!(s == crypto_auth_PRIMITIVE.as_bytes());
    }
}
