// crypto_auth_hmacsha512256.h

#[test]
fn test_crypto_auth_hmacsha512256_bytes() {
    assert!(
        unsafe { crypto_auth_hmacsha512256_bytes() as usize } == crypto_auth_hmacsha512256_BYTES
    )
}

#[test]
fn test_crypto_auth_hmacsha512256_keybytes() {
    assert!(
        unsafe { crypto_auth_hmacsha512256_keybytes() as usize }
            == crypto_auth_hmacsha512256_KEYBYTES
    )
}
