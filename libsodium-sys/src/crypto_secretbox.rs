// crypto_secretbox.h

#[test]
fn test_crypto_secretbox_keybytes() {
    assert!(unsafe { crypto_secretbox_keybytes() as usize } == crypto_secretbox_KEYBYTES)
}

#[test]
fn test_crypto_secretbox_noncebytes() {
    assert!(unsafe { crypto_secretbox_noncebytes() as usize } == crypto_secretbox_NONCEBYTES)
}

#[test]
fn test_crypto_secretbox_macbytes() {
    assert!(unsafe { crypto_secretbox_macbytes() as usize } == crypto_secretbox_MACBYTES)
}

#[test]
fn test_crypto_secretbox_primitive() {
    unsafe {
        let s = crypto_secretbox_primitive();
        let s = std::ffi::CStr::from_ptr(s).to_bytes();
        assert!(s == crypto_secretbox_PRIMITIVE.as_bytes());
    }
}
