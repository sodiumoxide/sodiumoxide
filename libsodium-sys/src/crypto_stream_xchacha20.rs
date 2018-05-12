// crypto_stream_xchacha20.h

#[test]
fn test_crypto_stream_xchacha20_keybytes() {
    assert!(
        unsafe { crypto_stream_xchacha20_keybytes() as usize } == crypto_stream_xchacha20_KEYBYTES
    )
}

#[test]
fn test_crypto_stream_xchacha20_noncebytes() {
    assert!(
        unsafe { crypto_stream_xchacha20_noncebytes() as usize }
            == crypto_stream_xchacha20_NONCEBYTES
    )
}
