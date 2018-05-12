// crypto_hash_sha256.h

#[test]
fn test_crypto_hash_sha256_bytes() {
    assert!(unsafe { crypto_hash_sha256_bytes() as usize } == crypto_hash_sha256_BYTES)
}
