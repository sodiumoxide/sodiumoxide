// crypto_aead_aes256gcm.h

pub const crypto_aead_aes256gcm_KEYBYTES: usize = 32;
pub const crypto_aead_aes256gcm_NSECBYTES: usize = 0;
pub const crypto_aead_aes256gcm_NPUBBYTES: usize = 12;
pub const crypto_aead_aes256gcm_ABYTES: usize = 16;

extern {
    pub fn crypto_aead_aes256gcm_is_available() -> c_int;
    pub fn crypto_aead_aes256gcm_keybytes() -> size_t;
    pub fn crypto_aead_aes256gcm_nsecbytes() -> size_t;
    pub fn crypto_aead_aes256gcm_npubbytes() -> size_t;
    pub fn crypto_aead_aes256gcm_abytes() -> size_t;
    pub fn crypto_aead_aes256gcm_encrypt(
        c: *mut u8,
        clen: *mut c_ulonglong,
        m: *const u8,
        mlen: c_ulonglong,
        ad: *const u8,
        adlen: c_ulonglong,
        nsec: *mut [u8; crypto_aead_aes256gcm_NSECBYTES],
        npub: *const [u8; crypto_aead_aes256gcm_NPUBBYTES],
        k: *const [u8; crypto_aead_aes256gcm_KEYBYTES]) -> c_int;
    pub fn crypto_aead_aes256gcm_decrypt(
        m: *mut u8,
        mlen: *mut c_ulonglong,
        nsec: *mut [u8; crypto_aead_aes256gcm_NSECBYTES],
        c: *const u8,
        clen: c_ulonglong,
        ad: *const u8,
        adlen: c_ulonglong,
        npub: *const [u8; crypto_aead_aes256gcm_NPUBBYTES],
        k: *const [u8; crypto_aead_aes256gcm_KEYBYTES]) -> c_int;
    pub fn crypto_aead_aes256gcm_encrypt_detached(
        c: *mut u8,
        mac: *mut u8,
        maclen: *mut c_ulonglong,
        m: *const u8,
        mlen: c_ulonglong,
        ad: *const u8,
        adlen: c_ulonglong,
        nsec: *mut [u8; crypto_aead_aes256gcm_NSECBYTES],
        npub: *const [u8; crypto_aead_aes256gcm_NPUBBYTES],
        k: *const [u8; crypto_aead_aes256gcm_KEYBYTES]) -> c_int;
    pub fn crypto_aead_aes256gcm_decrypt_detached(
        m: *mut u8,
        nsec: *mut [u8; crypto_aead_aes256gcm_NSECBYTES],
        c: *const u8,
        clen: c_ulonglong,
        mac: [u8; crypto_aead_aes256gcm_ABYTES],
        ad: *const u8,
        adlen: c_ulonglong,
        npub: *const [u8; crypto_aead_aes256gcm_NPUBBYTES],
        k: *const [u8; crypto_aead_aes256gcm_KEYBYTES]) -> c_int;
}


#[test]
fn test_crypto_aead_aes256gcm_keybytes() {
    assert!(unsafe { crypto_aead_aes256gcm_keybytes() as usize } ==
            crypto_aead_aes256gcm_KEYBYTES)
}
#[test]
fn test_crypto_aead_aes256gcm_nsecbytes() {
    assert!(unsafe { crypto_aead_aes256gcm_nsecbytes() as usize } ==
            crypto_aead_aes256gcm_NSECBYTES)
}
#[test]
fn test_crypto_aead_aes256gcm_npubbytes() {
    assert!(unsafe { crypto_aead_aes256gcm_npubbytes() as usize } ==
            crypto_aead_aes256gcm_NPUBBYTES)
}
#[test]
fn test_crypto_aead_chacha20poly1305_abytes() {
    assert!(unsafe { crypto_aead_aes256gcm_abytes() as usize } ==
            crypto_aead_aes256gcm_ABYTES)
}
