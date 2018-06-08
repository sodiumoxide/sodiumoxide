// crypto_onetimeauth_poly1305.h

use libsodium_sys::*;

#[test]
fn test_crypto_onetimeauth_poly1305_bytes() {
    assert!(
        unsafe { crypto_onetimeauth_poly1305_bytes() }
            == crypto_onetimeauth_poly1305_BYTES as usize
    )
}
#[test]
fn test_crypto_onetimeauth_poly1305_keybytes() {
    assert!(
        unsafe { crypto_onetimeauth_poly1305_keybytes() }
            == crypto_onetimeauth_poly1305_KEYBYTES as usize
    )
}
