// crypto_shorthash_siphash24.h

#[test]
fn test_crypto_shorthash_siphash24_bytes() {
    assert!(
        unsafe { crypto_shorthash_siphash24_bytes() as usize } == crypto_shorthash_siphash24_BYTES
    )
}

#[test]
fn test_crypto_shorthash_siphash24_keybytes() {
    assert!(
        unsafe { crypto_shorthash_siphash24_keybytes() as usize }
            == crypto_shorthash_siphash24_KEYBYTES
    )
}
