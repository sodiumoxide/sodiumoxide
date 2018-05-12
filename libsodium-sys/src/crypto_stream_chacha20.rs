// crypto_stream_chacha20.h

#[test]
fn test_crypto_stream_chacha20_keybytes() {
    assert!(
        unsafe { crypto_stream_chacha20_keybytes() as usize } == crypto_stream_chacha20_KEYBYTES
    )
}

#[test]
fn test_crypto_stream_chacha20_noncebytes() {
    assert!(
        unsafe { crypto_stream_chacha20_noncebytes() as usize }
            == crypto_stream_chacha20_NONCEBYTES
    )
}
