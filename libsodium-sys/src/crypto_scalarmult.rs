// crypto_scalarmult.h

#[test]
fn test_crypto_scalarmult_bytes() {
    assert_eq!(
        unsafe { crypto_scalarmult_bytes() as usize },
        crypto_scalarmult_BYTES
    );
}

#[test]
fn test_crypto_scalarmult_scalarbytes() {
    assert_eq!(
        unsafe { crypto_scalarmult_scalarbytes() as usize },
        crypto_scalarmult_SCALARBYTES
    );
}

#[test]
fn test_crypto_scalarmult_primitive() {
    unsafe {
        let s = crypto_scalarmult_primitive();
        let s = std::ffi::CStr::from_ptr(s).to_bytes();
        assert_eq!(s, crypto_scalarmult_PRIMITIVE.as_bytes());
    }
}
