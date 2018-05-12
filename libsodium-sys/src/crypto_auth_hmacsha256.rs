// crypto_auth_hmacsha256.h

#[test]
fn test_crypto_auth_hmacsha256_bytes() {
    assert!(unsafe { crypto_auth_hmacsha256_bytes() as usize } == crypto_auth_hmacsha256_BYTES)
}

#[test]
fn test_crypto_auth_hmacsha256_keybytes() {
    assert!(
        unsafe { crypto_auth_hmacsha256_keybytes() as usize } == crypto_auth_hmacsha256_KEYBYTES
    )
}
