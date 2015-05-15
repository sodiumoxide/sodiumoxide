// crypto_generichash_blake2b.h

pub const crypto_generichash_blake2b_BYTES_MIN: usize = 16;
pub const crypto_generichash_blake2b_BYTES_MAX: usize = 64;
pub const crypto_generichash_blake2b_BYTES: usize = 32;
pub const crypto_generichash_blake2b_KEYBYTES_MIN: usize = 16;
pub const crypto_generichash_blake2b_KEYBYTES_MAX: usize = 64;
pub const crypto_generichash_blake2b_KEYBYTES: usize = 32;
pub const crypto_generichash_blake2b_SALTBYTES: usize = 16;
pub const crypto_generichash_blake2b_PERSONALBYTES: usize = 16;


extern {
    pub fn crypto_generichash_blake2b_bytes_min() -> size_t;
    pub fn crypto_generichash_blake2b_bytes_max() -> size_t;
    pub fn crypto_generichash_blake2b_bytes() -> size_t;
    pub fn crypto_generichash_blake2b_keybytes_min() -> size_t;
    pub fn crypto_generichash_blake2b_keybytes_max() -> size_t;
    pub fn crypto_generichash_blake2b_keybytes() -> size_t;
    pub fn crypto_generichash_blake2b_saltbytes() -> size_t;
    pub fn crypto_generichash_blake2b_personalbytes() -> size_t;

    pub fn crypto_generichash_blake2b(
        out: *mut u8,
        outlen: size_t,
        in_: *const u8,
        inlen: c_ulonglong,
        key: *const u8,
        keylen: size_t)
        -> c_int;

    pub fn crypto_generichash_blake2b_salt_personal(
        out: *mut u8,
        outlen: size_t,
        in_: *const u8,
        inlen: c_ulonglong,
        key: *const u8,
        keylen: size_t,
        salt: *const [u8; crypto_generichash_blake2b_SALTBYTES],
        personal: *const [u8; crypto_generichash_blake2b_PERSONALBYTES])
        -> c_int;
}

#[test]
fn test_crypto_generichash_blake2b_bytes_min() {
    assert_eq!(unsafe { crypto_generichash_blake2b_bytes_min() as usize },
                        crypto_generichash_blake2b_BYTES_MIN)
}

#[test]
fn test_crypto_generichash_blake2b_bytes_max() {
    assert_eq!(unsafe { crypto_generichash_blake2b_bytes_max() as usize },
                        crypto_generichash_blake2b_BYTES_MAX)
}

#[test]
fn test_crypto_generichash_blake2b_bytes() {
    assert_eq!(unsafe { crypto_generichash_blake2b_bytes() as usize },
                        crypto_generichash_blake2b_BYTES)
}

#[test]
fn test_crypto_generichash_blake2b_keybytes_min() {
    assert_eq!(unsafe { crypto_generichash_blake2b_keybytes_min() as usize },
                        crypto_generichash_blake2b_KEYBYTES_MIN)
}

#[test]
fn test_crypto_generichash_blake2b_keybytes_max() {
    assert_eq!(unsafe { crypto_generichash_blake2b_keybytes_max() as usize },
                        crypto_generichash_blake2b_KEYBYTES_MAX)
}

#[test]
fn test_crypto_generichash_blake2b_keybytes() {
    assert_eq!(unsafe { crypto_generichash_blake2b_keybytes() as usize },
                        crypto_generichash_blake2b_KEYBYTES)
}

#[test]
fn test_crypto_generichash_blake2b_saltbytes() {
    assert_eq!(unsafe { crypto_generichash_blake2b_saltbytes() as usize },
                        crypto_generichash_blake2b_SALTBYTES)
}

#[test]
fn test_crypto_generichash_blake2b_personalbytes() {
    assert_eq!(unsafe { crypto_generichash_blake2b_personalbytes() as usize },
                        crypto_generichash_blake2b_PERSONALBYTES)
}
