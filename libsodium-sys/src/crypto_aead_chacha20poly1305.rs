// crypto_aead_chacha20poly1305.h

pub const crypto_aead_chacha20poly1305_KEYBYTES: usize = 32;
pub const crypto_aead_chacha20poly1305_NSECBYTES: usize = 0;
pub const crypto_aead_chacha20poly1305_NPUBBYTES: usize = 8;
pub const crypto_aead_chacha20poly1305_ABYTES: usize = 16;

pub const crypto_aead_chacha20poly1305_ietf_KEYBYTES: usize = 32;
pub const crypto_aead_chacha20poly1305_ietf_NSECBYTES: usize = 0;
pub const crypto_aead_chacha20poly1305_ietf_NPUBBYTES: usize = 12;
pub const crypto_aead_chacha20poly1305_ietf_ABYTES: usize = 16;

extern {
    pub fn crypto_aead_chacha20poly1305_keybytes() -> size_t;
    pub fn crypto_aead_chacha20poly1305_nsecbytes() -> size_t;
    pub fn crypto_aead_chacha20poly1305_npubbytes() -> size_t;
    pub fn crypto_aead_chacha20poly1305_abytes() -> size_t;

    pub fn crypto_aead_chacha20poly1305_ietf_keybytes() -> size_t;
    pub fn crypto_aead_chacha20poly1305_ietf_nsecbytes() -> size_t;
    pub fn crypto_aead_chacha20poly1305_ietf_npubbytes() -> size_t;
    pub fn crypto_aead_chacha20poly1305_ietf_abytes() -> size_t;

    pub fn crypto_aead_chacha20poly1305_encrypt(
        c: *mut u8,
        clen: *mut c_ulonglong,
        m: *const u8,
        mlen: c_ulonglong,
        ad: *const u8,
        adlen: c_ulonglong,
        nsec: *const [u8; crypto_aead_chacha20poly1305_NSECBYTES],
        npub: *const [u8; crypto_aead_chacha20poly1305_NPUBBYTES],
        k: *const [u8; crypto_aead_chacha20poly1305_KEYBYTES]) -> c_int;
    pub fn crypto_aead_chacha20poly1305_decrypt(
        m: *mut u8,
        mlen: *mut c_ulonglong,
        nsec: *mut [u8; crypto_aead_chacha20poly1305_NSECBYTES],
        c: *const u8,
        clen: c_ulonglong,
        ad: *const u8,
        adlen: c_ulonglong,
        npub: *const [u8; crypto_aead_chacha20poly1305_NPUBBYTES],
        k: *const [u8; crypto_aead_chacha20poly1305_KEYBYTES]) -> c_int;
    pub fn crypto_aead_chacha20poly1305_encrypt_detached(
        c: *mut u8,
        mac: *mut u8,
        maclen_p: *mut c_ulonglong,
        m: *const u8,
        mlen: c_ulonglong,
        ad: *const u8,
        adlen: c_ulonglong,
        nsec: *const [u8; crypto_aead_chacha20poly1305_NSECBYTES],
        npub: *const [u8; crypto_aead_chacha20poly1305_NPUBBYTES],
        k: *const [u8; crypto_aead_chacha20poly1305_KEYBYTES]) -> c_int;
    pub fn crypto_aead_chacha20poly1305_decrypt_detached(
        m: *mut u8,
        nsec: *mut [u8; crypto_aead_chacha20poly1305_NSECBYTES],
        c: *const u8,
        clen: c_ulonglong,
        mac: *const u8,
        ad: *const u8,
        adlen: c_ulonglong,
        npub: *const [u8; crypto_aead_chacha20poly1305_NPUBBYTES],
        k: *const [u8; crypto_aead_chacha20poly1305_KEYBYTES]) -> c_int;

    pub fn crypto_aead_chacha20poly1305_ietf_encrypt(
        c: *mut u8,
        clen: *mut c_ulonglong,
        m: *const u8,
        mlen: c_ulonglong,
        ad: *const u8,
        adlen: c_ulonglong,
        nsec: *const [u8; crypto_aead_chacha20poly1305_ietf_NSECBYTES],
        npub: *const [u8; crypto_aead_chacha20poly1305_ietf_NPUBBYTES],
        k: *const [u8; crypto_aead_chacha20poly1305_ietf_KEYBYTES]) -> c_int;
    pub fn crypto_aead_chacha20poly1305_ietf_decrypt(
        m: *mut u8,
        mlen: *mut c_ulonglong,
        nsec: *mut [u8; crypto_aead_chacha20poly1305_ietf_NSECBYTES],
        c: *const u8,
        clen: c_ulonglong,
        ad: *const u8,
        adlen: c_ulonglong,
        npub: *const [u8; crypto_aead_chacha20poly1305_ietf_NPUBBYTES],
        k: *const [u8; crypto_aead_chacha20poly1305_ietf_KEYBYTES]) -> c_int;
    pub fn crypto_aead_chacha20poly1305_ietf_encrypt_detached(
        c: *mut u8,
        mac: *mut u8,
        maclen_p: *mut c_ulonglong,
        m: *const u8,
        mlen: c_ulonglong,
        ad: *const u8,
        adlen: c_ulonglong,
        nsec: *const [u8; crypto_aead_chacha20poly1305_ietf_NSECBYTES],
        npub: *const [u8; crypto_aead_chacha20poly1305_ietf_NPUBBYTES],
        k: *const [u8; crypto_aead_chacha20poly1305_ietf_KEYBYTES]) -> c_int;
    pub fn crypto_aead_chacha20poly1305_ietf_decrypt_detached(
        m: *mut u8,
        nsec: *mut [u8; crypto_aead_chacha20poly1305_ietf_NSECBYTES],
        c: *const u8,
        clen: c_ulonglong,
        mac: *const u8,
        ad: *const u8,
        adlen: c_ulonglong,
        npub: *const [u8; crypto_aead_chacha20poly1305_ietf_NPUBBYTES],
        k: *const [u8; crypto_aead_chacha20poly1305_ietf_KEYBYTES]) -> c_int;
}

#[test]
fn test_crypto_aead_chacha20poly1305_keybytes() {
    assert!(unsafe { crypto_aead_chacha20poly1305_keybytes() as usize } ==
            crypto_aead_chacha20poly1305_KEYBYTES)
}
#[test]
fn test_crypto_aead_chacha20poly1305_nsecbytes() {
    assert!(unsafe { crypto_aead_chacha20poly1305_nsecbytes() as usize } ==
            crypto_aead_chacha20poly1305_NSECBYTES)
}
#[test]
fn test_crypto_aead_chacha20poly1305_npubbytes() {
    assert!(unsafe { crypto_aead_chacha20poly1305_npubbytes() as usize } ==
            crypto_aead_chacha20poly1305_NPUBBYTES)
}
#[test]
fn test_crypto_aead_chacha20poly1305_abytes() {
    assert!(unsafe { crypto_aead_chacha20poly1305_abytes() as usize } ==
            crypto_aead_chacha20poly1305_ABYTES)
}

#[test]
fn test_crypto_aead_chacha20poly1305_ietf_keybytes() {
    assert!(unsafe { crypto_aead_chacha20poly1305_ietf_keybytes() as usize } ==
            crypto_aead_chacha20poly1305_ietf_KEYBYTES)
}
#[test]
fn test_crypto_aead_chacha20poly1305_ietf_nsecbytes() {
    assert!(unsafe { crypto_aead_chacha20poly1305_ietf_nsecbytes() as usize } ==
            crypto_aead_chacha20poly1305_ietf_NSECBYTES)
}
#[test]
fn test_crypto_aead_chacha20poly1305_ietf_npubbytes() {
    assert!(unsafe { crypto_aead_chacha20poly1305_ietf_npubbytes() as usize } ==
            crypto_aead_chacha20poly1305_ietf_NPUBBYTES)
}
#[test]
fn test_crypto_aead_chacha20poly1305_ietf_abytes() {
    assert!(unsafe { crypto_aead_chacha20poly1305_ietf_abytes() as usize } ==
            crypto_aead_chacha20poly1305_ietf_ABYTES)
}