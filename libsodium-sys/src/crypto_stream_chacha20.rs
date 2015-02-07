// crypto_stream_chacha20.h

pub const crypto_stream_chacha20_KEYBYTES: usize = 32;
pub const crypto_stream_chacha20_NONCEBYTES: usize = 8;


extern {
    pub fn crypto_stream_chacha20_keybytes() -> size_t;
    pub fn crypto_stream_chacha20_noncebytes() -> size_t;
}


#[test]
fn test_crypto_stream_chacha20_keybytes() {
    assert!(unsafe { crypto_stream_chacha20_keybytes() as usize } ==
            crypto_stream_chacha20_KEYBYTES)
}
#[test]
fn test_crypto_stream_chacha20_noncebytes() {
    assert!(unsafe { crypto_stream_chacha20_noncebytes() as usize } ==
            crypto_stream_chacha20_NONCEBYTES)
}
