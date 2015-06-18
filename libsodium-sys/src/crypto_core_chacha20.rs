// crypto_core_chacha20.h

pub const crypto_core_chacha20_OUTPUTBYTES: usize = 64;
pub const crypto_core_chacha20_INPUTBYTES: usize = 16;
pub const crypto_core_chacha20_KEYBYTES: usize = 32;
pub const crypto_core_chacha20_CONSTBYTES: usize = 16;

extern {
    pub fn crypto_core_chacha20_outputbytes() -> size_t;
    pub fn crypto_core_chacha20_inputbytes() -> size_t;
    pub fn crypto_core_chacha20_keybytes() -> size_t;
    pub fn crypto_core_chacha20_constbytes() -> size_t;

    pub fn crypto_core_chacha20(
        out: *mut [u8; crypto_core_chacha20_OUTPUTBYTES],
        in_: *const [u8; crypto_core_chacha20_INPUTBYTES],
        k: *const [u8; crypto_core_chacha20_KEYBYTES],
        c: *const [u8; crypto_core_chacha20_CONSTBYTES]) -> c_int;
}

#[test]
fn test_crypto_core_chacha20_outputbytes() {
    assert!(unsafe {
        crypto_core_chacha20_outputbytes() as usize
    } == crypto_core_chacha20_OUTPUTBYTES)
}

#[test]
fn test_crypto_core_chacha20_inputbytes() {
    assert!(unsafe {
        crypto_core_chacha20_inputbytes() as usize
    } == crypto_core_chacha20_INPUTBYTES)
}

#[test]
fn test_crypto_core_chacha20_keybytes() {
    assert!(unsafe {
        crypto_core_chacha20_keybytes() as usize
    } == crypto_core_chacha20_KEYBYTES)
}

#[test]
fn test_crypto_core_chacha20_constbytes() {
    assert!(unsafe {
        crypto_core_chacha20_constbytes() as usize
    } == crypto_core_chacha20_CONSTBYTES)
}
