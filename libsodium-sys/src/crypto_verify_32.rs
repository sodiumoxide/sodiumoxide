// crypto_verify_32.h

#[test]
fn test_crypto_verify_32_bytes() {
    assert_eq!(
        unsafe { crypto_verify_32_bytes() as usize },
        crypto_verify_32_BYTES
    );
}
