// crypto_generichash.h

#[test]
fn test_crypto_generichash_bytes_min() {
    assert_eq!(
        unsafe { crypto_generichash_bytes_min() as usize },
        crypto_generichash_BYTES_MIN
    )
}

#[test]
fn test_crypto_generichash_bytes_max() {
    assert_eq!(
        unsafe { crypto_generichash_bytes_max() as usize },
        crypto_generichash_BYTES_MAX
    )
}

#[test]
fn test_crypto_generichash_bytes() {
    assert_eq!(
        unsafe { crypto_generichash_bytes() as usize },
        crypto_generichash_BYTES
    )
}

#[test]
fn test_crypto_generichash_keybytes_min() {
    assert_eq!(
        unsafe { crypto_generichash_keybytes_min() as usize },
        crypto_generichash_KEYBYTES_MIN
    )
}

#[test]
fn test_crypto_generichash_keybytes_max() {
    assert_eq!(
        unsafe { crypto_generichash_keybytes_max() as usize },
        crypto_generichash_KEYBYTES_MAX
    )
}

#[test]
fn test_crypto_generichash_keybytes() {
    assert_eq!(
        unsafe { crypto_generichash_keybytes() as usize },
        crypto_generichash_KEYBYTES
    )
}
#[test]
fn test_crypto_generichash_primitive() {
    unsafe {
        let s = crypto_generichash_primitive();
        let s = std::ffi::CStr::from_ptr(s).to_bytes();
        assert_eq!(s, crypto_generichash_PRIMITIVE.as_bytes());
    }
}

#[test]
fn test_crypto_generichash_statebytes() {
    assert!(unsafe { crypto_generichash_statebytes() } > 0);
}

#[test]
fn test_crypto_generichash() {
    let mut out = [0u8; crypto_generichash_BYTES];
    let m = [0u8; 64];
    let key = [0u8; crypto_generichash_KEYBYTES];

    assert_eq!(
        unsafe {
            crypto_generichash(
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

#[cfg(test)]
use std::mem;

#[test]
fn test_crypto_generichash_multipart() {
    let mut out = [0u8; crypto_generichash_BYTES];
    let m = [0u8; 64];
    let key = [0u8; crypto_generichash_KEYBYTES];

    let mut st = vec![0u8; (unsafe { crypto_generichash_statebytes() })];
    let pst = unsafe { mem::transmute::<*mut u8, *mut crypto_generichash_state>(st.as_mut_ptr()) };

    assert_eq!(
        unsafe { crypto_generichash_init(pst, key.as_ptr(), key.len(), out.len()) },
        0
    );

    assert_eq!(
        unsafe { crypto_generichash_update(pst, m.as_ptr(), m.len() as u64) },
        0
    );

    assert_eq!(
        unsafe { crypto_generichash_update(pst, m.as_ptr(), m.len() as u64) },
        0
    );

    assert_eq!(
        unsafe { crypto_generichash_final(pst, out.as_mut_ptr(), out.len()) },
        0
    );
}
