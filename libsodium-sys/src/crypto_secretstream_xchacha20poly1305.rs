// crypto_secretstream_xchacha20poly1305.h

#[repr(C)]
#[derive(Copy, Clone)]
pub struct crypto_secretstream_xchacha20poly1305_state {
    k: [u8; crypto_stream_chacha20_ietf_KEYBYTES],
    nonce: [u8; crypto_stream_chacha20_ietf_NONCEBYTES],
    _pad: [u8; 8],
}


pub const crypto_secretstream_xchacha20poly1305_ABYTES: usize = 1 + crypto_aead_xchacha20poly1305_ietf_ABYTES;
pub const crypto_secretstream_xchacha20poly1305_HEADERBYTES: usize = crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
pub const crypto_secretstream_xchacha20poly1305_KEYBYTES: usize = crypto_aead_xchacha20poly1305_ietf_KEYBYTES;
pub const crypto_secretstream_xchacha20poly1305_TAG_MESSAGE: u8 = 0x00;
pub const crypto_secretstream_xchacha20poly1305_TAG_PUSH: u8 = 0x01;
pub const crypto_secretstream_xchacha20poly1305_TAG_REKEY: u8 = 0x02;
pub const crypto_secretstream_xchacha20poly1305_TAG_FINAL: u8 = crypto_secretstream_xchacha20poly1305_TAG_PUSH | crypto_secretstream_xchacha20poly1305_TAG_REKEY;

extern {
    pub fn crypto_secretstream_xchacha20poly1305_abytes() -> size_t;
    pub fn crypto_secretstream_xchacha20poly1305_headerbytes() -> size_t;
    pub fn crypto_secretstream_xchacha20poly1305_keybytes() -> size_t;
    pub fn crypto_secretstream_xchacha20poly1305_messagebytes_max() -> size_t;
    pub fn crypto_secretstream_xchacha20poly1305_tag_message() -> u8;
    pub fn crypto_secretstream_xchacha20poly1305_tag_push() -> u8;
    pub fn crypto_secretstream_xchacha20poly1305_tag_rekey() -> u8;
    pub fn crypto_secretstream_xchacha20poly1305_tag_final() -> u8;

    pub fn crypto_secretstream_xchacha20poly1305_statebytes() -> size_t;
    
    pub fn crypto_secretstream_xchacha20poly1305_keygen(
        k: *mut [u8; crypto_secretstream_xchacha20poly1305_KEYBYTES]);

    pub fn crypto_secretstream_xchacha20poly1305_init_push(
        state: *mut crypto_secretstream_xchacha20poly1305_state,
        header: *mut [u8; crypto_secretstream_xchacha20poly1305_HEADERBYTES],
        k: *const [u8; crypto_secretstream_xchacha20poly1305_KEYBYTES]) -> c_int;
    
    pub fn crypto_secretstream_xchacha20poly1305_push(
        state: *mut crypto_secretstream_xchacha20poly1305_state,
        c: *mut u8,
        clen: *mut c_ulonglong,
        m: *const u8,
        mlen: c_ulonglong,
        ad: *const u8,
        adlen: c_ulonglong,
        tag: u8) -> c_int;
    
    pub fn crypto_secretstream_xchacha20poly1305_init_pull(
        state: *mut crypto_secretstream_xchacha20poly1305_state,
        header: *const [u8; crypto_secretstream_xchacha20poly1305_HEADERBYTES],
        k: *const [u8; crypto_secretstream_xchacha20poly1305_KEYBYTES]) -> c_int;
    
    pub fn crypto_secretstream_xchacha20poly1305_pull(
        state: *mut crypto_secretstream_xchacha20poly1305_state,
        m: *mut u8,
        mlen: *mut c_ulonglong,
        tag: *mut u8,
        c: *const u8,
        clen: c_ulonglong,
        ad: *const u8,
        adlen: c_ulonglong) -> c_int;
    
    pub fn crypto_secretstream_xchacha20poly1305_rekey(
        state: *mut crypto_secretstream_xchacha20poly1305_state) -> c_int;

}

#[test]
fn test_crypto_secretstream_xchacha20poly1305_abytes() {
    assert!(unsafe { crypto_secretstream_xchacha20poly1305_abytes() as usize } ==
            crypto_secretstream_xchacha20poly1305_ABYTES)
}

fn test_crypto_secretstream_xchacha20poly1305_headerbytes() {
    assert!(unsafe { crypto_secretstream_xchacha20poly1305_headerbytes() as usize } ==
            crypto_secretstream_xchacha20poly1305_HEADERBYTES)
}

fn test_crypto_secretstream_xchacha20poly1305_keybytes() {
    assert!(unsafe { crypto_secretstream_xchacha20poly1305_keybytes() as usize } ==
            crypto_secretstream_xchacha20poly1305_KEYBYTES)
}
