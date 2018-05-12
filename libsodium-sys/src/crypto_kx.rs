// crypto_kx.h

#[test]
fn test_crypto_kx_publickeybytes() {
    assert!(unsafe { crypto_kx_publickeybytes() } == crypto_kx_PUBLICKEYBYTES)
}

#[test]
fn test_crypto_kx_secretkeybytes() {
    assert!(unsafe { crypto_kx_secretkeybytes() } == crypto_kx_SECRETKEYBYTES)
}

#[test]
fn test_crypto_kx_seedbytes() {
    assert!(unsafe { crypto_kx_seedbytes() } == crypto_kx_SEEDBYTES)
}

#[test]
fn test_crypto_kx_sessionkeybytes() {
    assert!(unsafe { crypto_kx_sessionkeybytes() } == crypto_kx_SESSIONKEYBYTES)
}

#[test]
fn test_crypto_kx_primitive() {
    unsafe {
        let s = crypto_kx_primitive();
        let s = std::ffi::CStr::from_ptr(s).to_bytes();
        assert!(s == crypto_kx_PRIMITIVE.as_bytes());
    }
}
