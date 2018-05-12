// crypto_stream_salsa2012.h

#[test]
fn test_crypto_stream_salsa2012_keybytes() {
    assert!(
        unsafe { crypto_stream_salsa2012_keybytes() as usize } == crypto_stream_salsa2012_KEYBYTES
    )
}

#[test]
fn test_crypto_stream_salsa2012_noncebytes() {
    assert!(
        unsafe { crypto_stream_salsa2012_noncebytes() as usize }
            == crypto_stream_salsa2012_NONCEBYTES
    )
}
