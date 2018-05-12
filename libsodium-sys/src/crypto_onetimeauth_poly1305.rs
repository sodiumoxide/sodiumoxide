// crypto_onetimeauth_poly1305.h

#[test]
fn test_crypto_onetimeauth_poly1305_bytes() {
    assert!(
        unsafe { crypto_onetimeauth_poly1305_bytes() as usize }
            == crypto_onetimeauth_poly1305_BYTES
    )
}
#[test]
fn test_crypto_onetimeauth_poly1305_keybytes() {
    assert!(
        unsafe { crypto_onetimeauth_poly1305_keybytes() as usize }
            == crypto_onetimeauth_poly1305_KEYBYTES
    )
}
