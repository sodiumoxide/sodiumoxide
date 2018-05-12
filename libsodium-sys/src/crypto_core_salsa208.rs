// crypto_core_salsa208.h

#[test]
fn test_crypto_core_salsa208_outputbytes() {
    assert!(
        unsafe { crypto_core_salsa208_outputbytes() as usize } == crypto_core_salsa208_OUTPUTBYTES
    )
}

#[test]
fn test_crypto_core_salsa208_inputbytes() {
    assert!(
        unsafe { crypto_core_salsa208_inputbytes() as usize } == crypto_core_salsa208_INPUTBYTES
    )
}

#[test]
fn test_crypto_core_salsa208_keybytes() {
    assert!(unsafe { crypto_core_salsa208_keybytes() as usize } == crypto_core_salsa208_KEYBYTES)
}

#[test]
fn test_crypto_core_salsa208_constbytes() {
    assert!(
        unsafe { crypto_core_salsa208_constbytes() as usize } == crypto_core_salsa208_CONSTBYTES
    )
}
