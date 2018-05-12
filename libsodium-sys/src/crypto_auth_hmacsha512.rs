// crypto_auth_hmacsha512.h

#[test]
fn test_crypto_auth_hmacsha512_bytes() {
    assert!(unsafe { crypto_auth_hmacsha512_bytes() as usize } == crypto_auth_hmacsha512_BYTES)
}

#[test]
fn test_crypto_auth_hmacsha512_keybytes() {
    assert!(
        unsafe { crypto_auth_hmacsha512_keybytes() as usize } == crypto_auth_hmacsha512_KEYBYTES
    )
}
