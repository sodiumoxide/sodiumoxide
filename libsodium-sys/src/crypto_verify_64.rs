// crypto_verify_64.h

#[test]
fn test_crypto_verify_64_bytes() {
    assert_eq!(
        unsafe { crypto_verify_64_bytes() as usize },
        crypto_verify_64_BYTES
    );
}
