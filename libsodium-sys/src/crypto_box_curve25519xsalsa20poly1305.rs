// crypto_box_curve25519xsalsa20poly1305.h

#[test]
fn test_crypto_box_curve25519xsalsa20poly1305_seedbytes() {
    assert!(
        unsafe { crypto_box_curve25519xsalsa20poly1305_seedbytes() as usize }
            == crypto_box_curve25519xsalsa20poly1305_SEEDBYTES
    )
}

#[test]
fn test_crypto_box_curve25519xsalsa20poly1305_publickeybytes() {
    assert!(
        unsafe { crypto_box_curve25519xsalsa20poly1305_publickeybytes() as usize }
            == crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES
    )
}

#[test]
fn test_crypto_box_curve25519xsalsa20poly1305_secretkeybytes() {
    assert!(
        unsafe { crypto_box_curve25519xsalsa20poly1305_secretkeybytes() as usize }
            == crypto_box_curve25519xsalsa20poly1305_SECRETKEYBYTES
    )
}

#[test]
fn test_crypto_box_curve25519xsalsa20poly1305_beforenmbytes() {
    assert!(
        unsafe { crypto_box_curve25519xsalsa20poly1305_beforenmbytes() as usize }
            == crypto_box_curve25519xsalsa20poly1305_BEFORENMBYTES
    )
}

#[test]
fn test_crypto_box_curve25519xsalsa20poly1305_noncebytes() {
    assert!(
        unsafe { crypto_box_curve25519xsalsa20poly1305_noncebytes() as usize }
            == crypto_box_curve25519xsalsa20poly1305_NONCEBYTES
    )
}

#[test]
fn test_crypto_box_curve25519xsalsa20poly1305_zerobytes() {
    assert!(
        unsafe { crypto_box_curve25519xsalsa20poly1305_zerobytes() as usize }
            == crypto_box_curve25519xsalsa20poly1305_ZEROBYTES
    )
}

#[test]
fn test_crypto_box_curve25519xsalsa20poly1305_boxzerobytes() {
    assert!(
        unsafe { crypto_box_curve25519xsalsa20poly1305_boxzerobytes() as usize }
            == crypto_box_curve25519xsalsa20poly1305_BOXZEROBYTES
    )
}

#[test]
fn test_crypto_box_curve25519xsalsa20poly1305_macbytes() {
    assert!(
        unsafe { crypto_box_curve25519xsalsa20poly1305_macbytes() as usize }
            == crypto_box_curve25519xsalsa20poly1305_MACBYTES
    )
}
