// crypto_stream_salsa208.h

#[test]
fn test_crypto_stream_salsa208_keybytes() {
    assert!(
        unsafe { crypto_stream_salsa208_keybytes() as usize } == crypto_stream_salsa208_KEYBYTES
    )
}
#[test]
fn test_crypto_stream_salsa208_noncebytes() {
    assert!(
        unsafe { crypto_stream_salsa208_noncebytes() as usize }
            == crypto_stream_salsa208_NONCEBYTES
    )
}
