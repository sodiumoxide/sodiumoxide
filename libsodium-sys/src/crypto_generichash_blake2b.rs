// crypto_generichash_blake2b.h

#[test]
fn test_crypto_generichash_blake2b_bytes_min() {
    assert_eq!(
        unsafe { crypto_generichash_blake2b_bytes_min() as usize },
        crypto_generichash_blake2b_BYTES_MIN
    )
}

#[test]
fn test_crypto_generichash_blake2b_bytes_max() {
    assert_eq!(
        unsafe { crypto_generichash_blake2b_bytes_max() as usize },
        crypto_generichash_blake2b_BYTES_MAX
    )
}

#[test]
fn test_crypto_generichash_blake2b_bytes() {
    assert_eq!(
        unsafe { crypto_generichash_blake2b_bytes() as usize },
        crypto_generichash_blake2b_BYTES
    )
}

#[test]
fn test_crypto_generichash_blake2b_keybytes_min() {
    assert_eq!(
        unsafe { crypto_generichash_blake2b_keybytes_min() as usize },
        crypto_generichash_blake2b_KEYBYTES_MIN
    )
}

#[test]
fn test_crypto_generichash_blake2b_keybytes_max() {
    assert_eq!(
        unsafe { crypto_generichash_blake2b_keybytes_max() as usize },
        crypto_generichash_blake2b_KEYBYTES_MAX
    )
}

#[test]
fn test_crypto_generichash_blake2b_keybytes() {
    assert_eq!(
        unsafe { crypto_generichash_blake2b_keybytes() as usize },
        crypto_generichash_blake2b_KEYBYTES
    )
}

#[test]
fn test_crypto_generichash_blake2b_saltbytes() {
    assert_eq!(
        unsafe { crypto_generichash_blake2b_saltbytes() as usize },
        crypto_generichash_blake2b_SALTBYTES
    )
}

#[test]
fn test_crypto_generichash_blake2b_personalbytes() {
    assert_eq!(
        unsafe { crypto_generichash_blake2b_personalbytes() as usize },
        crypto_generichash_blake2b_PERSONALBYTES
    )
}

#[test]
fn test_crypto_generichash_blake2b() {
    let mut out = [0u8; crypto_generichash_blake2b_BYTES];
    let m = [0u8; 64];
    let key = [0u8; crypto_generichash_blake2b_KEYBYTES];

    assert_eq!(
        unsafe {
            crypto_generichash_blake2b(
                out.as_mut_ptr(),
                out.len(),
                m.as_ptr(),
                m.len() as u64,
                key.as_ptr(),
                key.len(),
            )
        },
        0
    );
}

#[test]
fn test_crypto_generichash_blake2b_salt_personal() {
    let mut out = [0u8; crypto_generichash_blake2b_BYTES];
    let m = [0u8; 64];
    let key = [0u8; crypto_generichash_blake2b_KEYBYTES];
    let salt = [0u8; crypto_generichash_blake2b_SALTBYTES];
    let personal = [0u8; crypto_generichash_blake2b_PERSONALBYTES];

    assert_eq!(
        unsafe {
            crypto_generichash_blake2b_salt_personal(
                out.as_mut_ptr(),
                out.len(),
                m.as_ptr(),
                m.len() as u64,
                key.as_ptr(),
                key.len(),
                &salt,
                &personal,
            )
        },
        0
    );
}
