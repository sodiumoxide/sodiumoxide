// crypto_stream_xchacha20.h

pub const crypto_stream_xchacha20_KEYBYTES: usize = 32;
pub const crypto_stream_xchacha20_NONCEBYTES: usize = 24;

extern {
    pub fn crypto_stream_xchacha20(
        c: *mut u8,
        clen: c_ulonglong,
        n: *const [u8; crypto_stream_xchacha20_NONCEBYTES],
        k: *const [u8; crypto_stream_xchacha20_KEYBYTES]) -> c_int;
    pub fn crypto_stream_xchacha20_xor(
        c: *mut u8,
        m: *const u8,
        mlen: c_ulonglong,
        n: *const [u8; crypto_stream_xchacha20_NONCEBYTES],
        k: *const [u8; crypto_stream_xchacha20_KEYBYTES]) -> c_int;
    pub fn crypto_stream_xchacha20_xor_ic(
        c: *mut u8,
        m: *const u8,
        mlen: c_ulonglong,
        n: *const [u8; crypto_stream_xchacha20_NONCEBYTES],
        ic: uint64_t,
        k: *const [u8; crypto_stream_xchacha20_KEYBYTES]) -> c_int;
    pub fn crypto_stream_xchacha20_keybytes() -> size_t;
    pub fn crypto_stream_xchacha20_noncebytes() -> size_t;
}


#[test]
fn test_crypto_stream_xchacha20_keybytes() {
    assert!(unsafe { crypto_stream_xchacha20_keybytes() as usize } ==
            crypto_stream_xchacha20_KEYBYTES)
}
#[test]
fn test_crypto_stream_xchacha20_noncebytes() {
    assert!(unsafe { crypto_stream_xchacha20_noncebytes() as usize } ==
            crypto_stream_xchacha20_NONCEBYTES)
}
