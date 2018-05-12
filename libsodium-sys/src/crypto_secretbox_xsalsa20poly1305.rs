// crypto_secretbox_xsalsa20poly1305.h

#[test]
fn test_crypto_secretbox_xsalsa20poly1305_keybytes() {
    assert!(
        unsafe { crypto_secretbox_xsalsa20poly1305_keybytes() as usize }
            == crypto_secretbox_xsalsa20poly1305_KEYBYTES
    )
}

#[test]
fn test_crypto_secretbox_xsalsa20poly1305_noncebytes() {
    assert!(
        unsafe { crypto_secretbox_xsalsa20poly1305_noncebytes() as usize }
            == crypto_secretbox_xsalsa20poly1305_NONCEBYTES
    )
}

#[test]
fn test_crypto_secretbox_xsalsa20poly1305_zerobytes() {
    assert!(
        unsafe { crypto_secretbox_xsalsa20poly1305_zerobytes() as usize }
            == crypto_secretbox_xsalsa20poly1305_ZEROBYTES
    )
}

#[test]
fn test_crypto_secretbox_xsalsa20poly1305_boxzerobytes() {
    assert!(
        unsafe { crypto_secretbox_xsalsa20poly1305_boxzerobytes() as usize }
            == crypto_secretbox_xsalsa20poly1305_BOXZEROBYTES
    )
}

#[test]
fn test_crypto_secretbox_xsalsa20poly1305_macbytes() {
    assert!(
        unsafe { crypto_secretbox_xsalsa20poly1305_macbytes() as usize }
            == crypto_secretbox_xsalsa20poly1305_MACBYTES
    )
}
