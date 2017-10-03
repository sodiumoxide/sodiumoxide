// crypto_kdf.h

pub const crypto_kdf_BYTES_MIN: usize = crypto_kdf_blake2b_BYTES_MIN;
pub const crypto_kdf_BYTES_MAX: usize = crypto_kdf_blake2b_BYTES_MAX;
pub const crypto_kdf_CONTEXTBYTES: usize = crypto_kdf_blake2b_CONTEXTBYTES;
pub const crypto_kdf_KEYBYTES: usize = crypto_kdf_blake2b_KEYBYTES;
pub const crypto_kdf_PRIMITIVE: &'static str = "blake2b";

extern {
    pub fn crypto_kdf_bytes_min() -> size_t;
    pub fn crypto_kdf_bytes_max() -> size_t;
    pub fn crypto_kdf_contextbytes() -> size_t;
    pub fn crypto_kdf_keybytes() -> size_t;
    pub fn crypto_kdf_primitive() -> *const c_char;

    pub fn crypto_kdf_derive_from_key(
        subkey: *mut u8,
        subkey_len: size_t,
        subkey_id: uint64_t,
        ctx: *const [u8; crypto_kdf_CONTEXTBYTES],
        key: *const [u8; crypto_kdf_KEYBYTES])
        -> c_int;
}

#[test]
fn test_crypto_kdf_bytes_min() {
    assert_eq!(unsafe { crypto_kdf_bytes_min() as usize },
                        crypto_kdf_BYTES_MIN)
}

#[test]
fn test_crypto_kdf_bytes_max() {
    assert_eq!(unsafe { crypto_kdf_bytes_max() as usize },
                        crypto_kdf_BYTES_MAX)
}

#[test]
fn test_crypto_kdf_contextbytes() {
    assert_eq!(unsafe { crypto_kdf_contextbytes() as usize },
                        crypto_kdf_CONTEXTBYTES)
}

#[test]
fn test_crypto_kdf_keybytes() {
    assert_eq!(unsafe { crypto_kdf_keybytes() as usize },
                        crypto_kdf_KEYBYTES)
}

#[test]
fn test_crypto_kdf_primitive() {
    unsafe {
        let s = crypto_kdf_primitive();
        let s = std::ffi::CStr::from_ptr(s).to_bytes();
        assert_eq!(s, crypto_kdf_PRIMITIVE.as_bytes());
    }
}

#[test]
fn test_crypto_kdf_derive_from_key() {
    let mut subkey = [0u8; 32];
    let key = [207, 248, 208, 158, 90, 30, 63, 85, 104, 123, 203, 93, 129, 163, 140, 191, 174, 127, 178, 201, 155, 186, 237, 109, 171, 50, 188, 116, 155, 105, 247, 85];

    assert_eq!(unsafe {
        crypto_kdf_derive_from_key(
            subkey.as_mut_ptr(),
            subkey.len(),
            0,
            b"kdf_test",
            &key)
    }, 0);

    assert_eq!(subkey, [177, 166, 148, 67, 88, 130, 103, 19, 144, 61, 16, 223, 114, 206, 92, 204, 71, 77, 16, 139, 142, 109, 88, 30, 162, 125, 22, 80, 76, 97, 27, 244]);
}
