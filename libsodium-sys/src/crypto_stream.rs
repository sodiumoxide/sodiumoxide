// crypto_stream.h

#[test]
fn test_crypto_stream_keybytes() {
    assert!(unsafe { crypto_stream_keybytes() as usize } == crypto_stream_KEYBYTES)
}

#[test]
fn test_crypto_stream_noncebytes() {
    assert!(unsafe { crypto_stream_noncebytes() as usize } == crypto_stream_NONCEBYTES)
}

#[test]
fn test_crypto_stream_primitive() {
    unsafe {
        let s = crypto_stream_primitive();
        let s = std::ffi::CStr::from_ptr(s).to_bytes();
        assert!(s == crypto_stream_PRIMITIVE.as_bytes());
    }
}
