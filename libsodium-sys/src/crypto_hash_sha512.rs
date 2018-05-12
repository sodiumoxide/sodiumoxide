// crypto_hash_sha512.h

#[test]
fn test_crypto_hash_sha512_bytes() {
    assert!(unsafe { crypto_hash_sha512_bytes() as usize } == crypto_hash_sha512_BYTES)
}
