// crypto_core_salsa2012.h

#[test]
fn test_crypto_core_salsa2012_outputbytes() {
    assert!(
        unsafe { crypto_core_salsa2012_outputbytes() as usize }
            == crypto_core_salsa2012_OUTPUTBYTES
    )
}

#[test]
fn test_crypto_core_salsa2012_inputbytes() {
    assert!(
        unsafe { crypto_core_salsa2012_inputbytes() as usize } == crypto_core_salsa2012_INPUTBYTES
    )
}

#[test]
fn test_crypto_core_salsa2012_keybytes() {
    assert!(unsafe { crypto_core_salsa2012_keybytes() as usize } == crypto_core_salsa2012_KEYBYTES)
}

#[test]
fn test_crypto_core_salsa2012_constbytes() {
    assert!(
        unsafe { crypto_core_salsa2012_constbytes() as usize } == crypto_core_salsa2012_CONSTBYTES
    )
}
