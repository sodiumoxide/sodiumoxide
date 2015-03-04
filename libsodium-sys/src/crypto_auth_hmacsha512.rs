// crypto_auth_hmacsha512.h

pub const crypto_auth_hmacsha512_BYTES: usize = 64;
pub const crypto_auth_hmacsha512_KEYBYTES: usize = 32;


extern {
    pub fn crypto_auth_hmacsha512(
        a: *mut [u8; crypto_auth_hmacsha512_BYTES],
        m: *const u8,
        mlen: c_ulonglong,
        k: *const [u8; crypto_auth_hmacsha512_KEYBYTES]) -> c_int;
    pub fn crypto_auth_hmacsha512_verify(
        a: *const [u8; crypto_auth_hmacsha512_BYTES],
        m: *const u8,
        mlen: c_ulonglong,
        k: *const [u8; crypto_auth_hmacsha512_KEYBYTES]) -> c_int;
    pub fn crypto_auth_hmacsha512_bytes() -> size_t;
    pub fn crypto_auth_hmacsha512_keybytes() -> size_t;
}


#[test]
fn test_crypto_auth_hmacsha512_bytes() {
    assert!(unsafe { crypto_auth_hmacsha512_bytes() as usize } ==
            crypto_auth_hmacsha512_BYTES)
}
#[test]
fn test_crypto_auth_hmacsha512_keybytes() {
    assert!(unsafe { crypto_auth_hmacsha512_keybytes() as usize } ==
            crypto_auth_hmacsha512_KEYBYTES)
}
