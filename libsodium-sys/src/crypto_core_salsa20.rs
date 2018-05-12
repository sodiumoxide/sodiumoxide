// crypto_core_salsa20.h

#[test]
fn test_crypto_core_salsa20_outputbytes() {
    assert!(
        unsafe { crypto_core_salsa20_outputbytes() as usize } == crypto_core_salsa20_OUTPUTBYTES
    )
}

#[test]
fn test_crypto_core_salsa20_inputbytes() {
    assert!(unsafe { crypto_core_salsa20_inputbytes() as usize } == crypto_core_salsa20_INPUTBYTES)
}

#[test]
fn test_crypto_core_salsa20_keybytes() {
    assert!(unsafe { crypto_core_salsa20_keybytes() as usize } == crypto_core_salsa20_KEYBYTES)
}

#[test]
fn test_crypto_core_salsa20_constbytes() {
    assert!(unsafe { crypto_core_salsa20_constbytes() as usize } == crypto_core_salsa20_CONSTBYTES)
}
