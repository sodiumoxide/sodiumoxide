// crypto_onetimeauth.h

#[test]
fn test_crypto_onetimeauth_bytes() {
    assert!(unsafe { crypto_onetimeauth_bytes() as usize } == crypto_onetimeauth_BYTES)
}

#[test]
fn test_crypto_onetimeauth_keybytes() {
    assert!(unsafe { crypto_onetimeauth_keybytes() as usize } == crypto_onetimeauth_KEYBYTES)
}

#[test]
fn test_crypto_onetimeauth_primitive() {
    unsafe {
        let s = crypto_onetimeauth_primitive();
        let s = std::ffi::CStr::from_ptr(s).to_bytes();
        assert!(s == crypto_onetimeauth_PRIMITIVE.as_bytes());
    }
}
