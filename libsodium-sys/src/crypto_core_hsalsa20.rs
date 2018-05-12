// crypto_core_hsalsa20.h

#[test]
fn test_crypto_core_hsalsa20_outputbytes() {
    assert!(
        unsafe { crypto_core_hsalsa20_outputbytes() as usize } == crypto_core_hsalsa20_OUTPUTBYTES
    )
}
#[test]
fn test_crypto_core_hsalsa20_inputbytes() {
    assert!(
        unsafe { crypto_core_hsalsa20_inputbytes() as usize } == crypto_core_hsalsa20_INPUTBYTES
    )
}
#[test]
fn test_crypto_core_hsalsa20_keybytes() {
    assert!(unsafe { crypto_core_hsalsa20_keybytes() as usize } == crypto_core_hsalsa20_KEYBYTES)
}
#[test]
fn test_crypto_core_hsalsa20_constbytes() {
    assert!(
        unsafe { crypto_core_hsalsa20_constbytes() as usize } == crypto_core_hsalsa20_CONSTBYTES
    )
}
