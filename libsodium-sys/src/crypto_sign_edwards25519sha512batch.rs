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
}
