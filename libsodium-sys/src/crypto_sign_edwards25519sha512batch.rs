// crypto_sign_edwards25519sha512batch.h

pub const crypto_sign_edwards25519sha512batch_BYTES: usize = 64;
pub const crypto_sign_edwards25519sha512batch_PUBLICKEYBYTES: usize = 32;
pub const crypto_sign_edwards25519sha512batch_SECRETKEYBYTES: usize = 64;


extern {
    pub fn crypto_sign_edwards25519sha512batch_keypair(
        pk: *mut [u8; crypto_sign_edwards25519sha512batch_PUBLICKEYBYTES],
        sk: *mut [u8; crypto_sign_edwards25519sha512batch_SECRETKEYBYTES])
        -> c_int;
    pub fn crypto_sign_edwards25519sha512batch(
        sm: *mut u8,
        smlen: *mut c_ulonglong,
        m: *const u8,
        mlen: c_ulonglong,
        sk: *const [u8; crypto_sign_edwards25519sha512batch_SECRETKEYBYTES])
        -> c_int;
    pub fn crypto_sign_edwards25519sha512batch_open(
        m: *mut u8,
        mlen: *mut c_ulonglong,
        sm: *const u8,
        smlen: c_ulonglong,
        pk: *const [u8; crypto_sign_edwards25519sha512batch_PUBLICKEYBYTES]) ->
        c_int;
    pub fn crypto_sign_edwards25519sha512batch_bytes() -> size_t;
    pub fn crypto_sign_edwards25519sha512batch_publickeybytes() -> size_t;
    pub fn crypto_sign_edwards25519sha512batch_secretkeybytes() -> size_t;
}


#[test]
fn test_crypto_sign_edwards25519sha512batch_bytes() {
    assert!(unsafe {
        crypto_sign_edwards25519sha512batch_bytes() as usize
    } == crypto_sign_edwards25519sha512batch_BYTES)
}
#[test]
fn test_crypto_sign_edwards25519sha512batch_publickeybytes() {
    assert!(unsafe {
        crypto_sign_edwards25519sha512batch_publickeybytes() as usize
    } == crypto_sign_edwards25519sha512batch_PUBLICKEYBYTES)
}
#[test]
fn test_crypto_sign_edwards25519sha512batch_secretkeybytes() {
    assert!(unsafe {
        crypto_sign_edwards25519sha512batch_secretkeybytes() as usize
    } == crypto_sign_edwards25519sha512batch_SECRETKEYBYTES)
}
