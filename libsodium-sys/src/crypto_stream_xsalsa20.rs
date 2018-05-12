// crypto_stream_xsalsa20.h

#[test]
fn test_crypto_stream_xsalsa20_keybytes() {
    assert!(
        unsafe { crypto_stream_xsalsa20_keybytes() as usize } == crypto_stream_xsalsa20_KEYBYTES
    )
}

#[test]
fn test_crypto_stream_xsalsa20_noncebytes() {
    assert!(
        unsafe { crypto_stream_xsalsa20_noncebytes() as usize }
            == crypto_stream_xsalsa20_NONCEBYTES
    )
}
