// crypto_sign_ed25519.h

#[test]
fn test_crypto_sign_ed25519_bytes() {
    assert!(unsafe { crypto_sign_ed25519_bytes() as usize } == crypto_sign_ed25519_BYTES)
}

#[test]
fn test_crypto_sign_ed25519_seedbytes() {
    assert!(unsafe { crypto_sign_ed25519_seedbytes() as usize } == crypto_sign_ed25519_SEEDBYTES)
}

#[test]
fn test_crypto_sign_ed25519_publickeybytes() {
    assert!(
        unsafe { crypto_sign_ed25519_publickeybytes() as usize }
            == crypto_sign_ed25519_PUBLICKEYBYTES
    )
}

#[test]
fn test_crypto_sign_ed25519_secretkeybytes() {
    assert!(
        unsafe { crypto_sign_ed25519_secretkeybytes() as usize }
            == crypto_sign_ed25519_SECRETKEYBYTES
    )
}
