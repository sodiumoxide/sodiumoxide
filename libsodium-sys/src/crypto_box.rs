// crypto_box.h

#[test]
fn test_crypto_box_seedbytes() {
    assert!(unsafe { crypto_box_seedbytes() as usize } == crypto_box_SEEDBYTES)
}

#[test]
fn test_crypto_box_publickeybytes() {
    assert!(unsafe { crypto_box_publickeybytes() as usize } == crypto_box_PUBLICKEYBYTES)
}

#[test]
fn test_crypto_box_secretkeybytes() {
    assert!(unsafe { crypto_box_secretkeybytes() as usize } == crypto_box_SECRETKEYBYTES)
}

#[test]
fn test_crypto_box_beforenmbytes() {
    assert!(unsafe { crypto_box_beforenmbytes() as usize } == crypto_box_BEFORENMBYTES)
}

#[test]
fn test_crypto_box_noncebytes() {
    assert!(unsafe { crypto_box_noncebytes() as usize } == crypto_box_NONCEBYTES)
}

#[test]
fn test_crypto_box_zerobytes() {
    assert!(unsafe { crypto_box_zerobytes() as usize } == crypto_box_ZEROBYTES)
}

#[test]
fn test_crypto_box_boxzerobytes() {
    assert!(unsafe { crypto_box_boxzerobytes() as usize } == crypto_box_BOXZEROBYTES)
}

#[test]
fn test_crypto_box_macbytes() {
    assert!(unsafe { crypto_box_macbytes() as usize } == crypto_box_MACBYTES)
}

#[test]
fn test_crypto_box_primitive() {
    unsafe {
        let s = crypto_box_primitive();
        let s = std::ffi::CStr::from_ptr(s).to_bytes();
        assert!(s == crypto_box_PRIMITIVE.as_bytes());
    }
}

#[test]
fn test_crypto_box_sealbytes() {
    assert!(unsafe { crypto_box_sealbytes() as usize } == crypto_box_SEALBYTES)
}
