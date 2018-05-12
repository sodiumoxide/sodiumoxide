// crypto_hash.h

#[test]
fn test_crypto_hash_bytes() {
    assert!(unsafe { crypto_hash_bytes() as usize } == crypto_hash_BYTES)
}

#[test]
fn test_crypto_hash_primitive() {
    unsafe {
        let s = crypto_hash_primitive();
        let s = std::ffi::CStr::from_ptr(s).to_bytes();
        assert!(s == crypto_hash_PRIMITIVE.as_bytes());
    }
}
