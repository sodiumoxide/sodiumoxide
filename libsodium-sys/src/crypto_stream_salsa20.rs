// crypto_stream_salsa20.h

#[test]
fn test_crypto_stream_salsa20_keybytes() {
    assert!(unsafe { crypto_stream_salsa20_keybytes() as usize } == crypto_stream_salsa20_KEYBYTES)
}

#[test]
fn test_crypto_stream_salsa20_noncebytes() {
    assert!(
        unsafe { crypto_stream_salsa20_noncebytes() as usize } == crypto_stream_salsa20_NONCEBYTES
    )
}
