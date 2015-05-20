// crypto_generichash.h

pub const crypto_generichash_BYTES_MIN: usize = crypto_generichash_blake2b_BYTES_MIN;
pub const crypto_generichash_BYTES_MAX: usize = crypto_generichash_blake2b_BYTES_MAX;
pub const crypto_generichash_BYTES: usize = crypto_generichash_blake2b_BYTES;
pub const crypto_generichash_KEYBYTES_MIN: usize = crypto_generichash_blake2b_KEYBYTES_MIN;
pub const crypto_generichash_KEYBYTES_MAX: usize = crypto_generichash_blake2b_KEYBYTES_MAX;
pub const crypto_generichash_KEYBYTES: usize = crypto_generichash_blake2b_KEYBYTES;
pub const crypto_generichash_PRIMITIVE: &'static str = "blake2b";

extern {
    pub fn crypto_generichash_bytes_min() -> size_t;
    pub fn crypto_generichash_bytes_max() -> size_t;
    pub fn crypto_generichash_bytes() -> size_t;
    pub fn crypto_generichash_keybytes_min() -> size_t;
    pub fn crypto_generichash_keybytes_max() -> size_t;
    pub fn crypto_generichash_keybytes() -> size_t;
    pub fn crypto_generichash_primitive() -> *const c_char;

    pub fn crypto_generichash(
        out: *mut u8,
        outlen: size_t,
        in_: *const u8,
        inlen: c_ulonglong,
        key: *const u8,
        keylen: size_t)
        -> c_int;
}

#[test]
fn test_crypto_generichash_bytes_min() {
    assert_eq!(unsafe { crypto_generichash_bytes_min() as usize },
                        crypto_generichash_BYTES_MIN)
}

#[test]
fn test_crypto_generichash_bytes_max() {
    assert_eq!(unsafe { crypto_generichash_bytes_max() as usize },
                        crypto_generichash_BYTES_MAX)
}

#[test]
fn test_crypto_generichash_bytes() {
    assert_eq!(unsafe { crypto_generichash_bytes() as usize },
                        crypto_generichash_BYTES)
}

#[test]
fn test_crypto_generichash_keybytes_min() {
    assert_eq!(unsafe { crypto_generichash_keybytes_min() as usize },
                        crypto_generichash_KEYBYTES_MIN)
}

#[test]
fn test_crypto_generichash_keybytes_max() {
    assert_eq!(unsafe { crypto_generichash_keybytes_max() as usize },
                        crypto_generichash_KEYBYTES_MAX)
}

#[test]
fn test_crypto_generichash_keybytes() {
    assert_eq!(unsafe { crypto_generichash_keybytes() as usize },
                        crypto_generichash_KEYBYTES)
}
#[test]
fn test_crypto_generichash_primitive() {
    unsafe {
        let s = crypto_generichash_primitive();
        let s = std::ffi::CStr::from_ptr(s).to_bytes();
        assert_eq!(s, crypto_generichash_PRIMITIVE.as_bytes());
    }
}
