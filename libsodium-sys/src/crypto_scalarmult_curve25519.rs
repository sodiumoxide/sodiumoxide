// crypto_scalarmult_curve25519.h

#[test]
fn test_crypto_scalarmult_curve25519_bytes() {
    assert_eq!(
        unsafe { crypto_scalarmult_curve25519_bytes() as usize },
        crypto_scalarmult_curve25519_BYTES
    );
}

#[test]
fn test_crypto_scalarmult_curve25519_scalarbytes() {
    assert_eq!(
        unsafe { crypto_scalarmult_curve25519_scalarbytes() as usize },
        crypto_scalarmult_curve25519_SCALARBYTES
    );
}
