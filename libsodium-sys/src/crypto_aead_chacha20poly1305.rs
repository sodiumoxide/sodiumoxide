// crypto_aead_chacha20poly1305.h

#[test]
fn test_crypto_aead_chacha20poly1305_keybytes() {
    assert!(
        unsafe { crypto_aead_chacha20poly1305_keybytes() as usize }
            == crypto_aead_chacha20poly1305_KEYBYTES
    )
}

#[test]
fn test_crypto_aead_chacha20poly1305_nsecbytes() {
    assert!(
        unsafe { crypto_aead_chacha20poly1305_nsecbytes() as usize }
            == crypto_aead_chacha20poly1305_NSECBYTES
    )
}

#[test]
fn test_crypto_aead_chacha20poly1305_npubbytes() {
    assert!(
        unsafe { crypto_aead_chacha20poly1305_npubbytes() as usize }
            == crypto_aead_chacha20poly1305_NPUBBYTES
    )
}

#[test]
fn test_crypto_aead_chacha20poly1305_abytes() {
    assert!(
        unsafe { crypto_aead_chacha20poly1305_abytes() as usize }
            == crypto_aead_chacha20poly1305_ABYTES
    )
}

#[test]
fn test_crypto_aead_chacha20poly1305_ietf_keybytes() {
    assert!(
        unsafe { crypto_aead_chacha20poly1305_ietf_keybytes() as usize }
            == crypto_aead_chacha20poly1305_ietf_KEYBYTES
    )
}

#[test]
fn test_crypto_aead_chacha20poly1305_ietf_nsecbytes() {
    assert!(
        unsafe { crypto_aead_chacha20poly1305_ietf_nsecbytes() as usize }
            == crypto_aead_chacha20poly1305_ietf_NSECBYTES
    )
}

#[test]
fn test_crypto_aead_chacha20poly1305_ietf_npubbytes() {
    assert!(
        unsafe { crypto_aead_chacha20poly1305_ietf_npubbytes() as usize }
            == crypto_aead_chacha20poly1305_ietf_NPUBBYTES
    )
}

#[test]
fn test_crypto_aead_chacha20poly1305_ietf_abytes() {
    assert!(
        unsafe { crypto_aead_chacha20poly1305_ietf_abytes() as usize }
            == crypto_aead_chacha20poly1305_ietf_ABYTES
    )
}
