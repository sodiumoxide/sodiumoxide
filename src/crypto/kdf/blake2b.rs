//! `blake2b` is the current default key derivation scheme of `libsodium`.

use ffi;

/// Number of bytes in a `Key`.
pub const KEYBYTES: usize = ffi::crypto_kdf_blake2b_KEYBYTES as usize;

/// Number of bytes in a `Context`
pub const CONTEXTBYTES: usize = ffi::crypto_kdf_blake2b_CONTEXTBYTES as usize;

/// Number of bytes in a `SubKey`.
pub const SUBKEYBYTES: usize = 32;

new_type! {
    /// `Key` for key derivation.
    public Key(KEYBYTES);
}

new_type! {
    /// `SubKey` from key derivation.
    public SubKey(SUBKEYBYTES);
}

/// `gen_key()` randomly generates a key for key derivation.
///
/// THREAD SAFETY: `gen_key()` is thread-safe provided that you have
/// called `sodiumoxide::init()` once before using any other function
/// from sodiumoxide.
pub fn gen_key() -> Key {
    use randombytes::randombytes_into;

    let mut key = [0; KEYBYTES];
    randombytes_into(&mut key);
    Key(key)
}

/// `derive_from_key` derives the subkey_id-th `SubKey` from the master key `key` and the context `ctx`.
pub fn derive_from_key(subkey_id: u64, ctx: [u8; CONTEXTBYTES], key: &Key) -> Result<SubKey, ()> {
    unsafe {
        let mut subkey = SubKey([0u8; SUBKEYBYTES]);
        let r = ffi::crypto_kdf_blake2b_derive_from_key(
            subkey.0.as_mut_ptr(),
            SUBKEYBYTES,
            subkey_id,
            ctx.as_ptr() as *mut i8,
            key.0.as_ptr(),
        );
        if r != 0 {
            Err(())
        } else {
            Ok(subkey)
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_vectors() {
        // Libsodium tests do not contain any test-vectors for `crypto_kdf_derive_from_key`.
        // The test vectors were generated using the initial implementation of this module
        // and only protect against new errors. They do not actually verify the implementation.
        {
            let key = Key([0u8; KEYBYTES]);
            let ctx = [0u8; CONTEXTBYTES];
            let subkey1 = derive_from_key(1, ctx, &key).unwrap();
            let subkey2 = derive_from_key(2, ctx, &key).unwrap();
            let subkey3 = derive_from_key(3, ctx, &key).unwrap();

            assert_eq!(
                subkey1,
                SubKey([
                    0x35, 0x87, 0xb8, 0x68, 0xc7, 0xc5, 0x04, 0x95, 0xf0, 0xe8, 0x36, 0xd9, 0x93,
                    0x58, 0x49, 0xff, 0x06, 0x5b, 0x53, 0x0b, 0xe2, 0x82, 0xe5, 0xd3, 0x56, 0x7e,
                    0xda, 0x61, 0x5d, 0x91, 0x01, 0x38,
                ])
            );
            assert_eq!(
                subkey2,
                SubKey([
                    0x1f, 0xde, 0x21, 0x0b, 0xc5, 0x49, 0xc4, 0x79, 0x67, 0xcb, 0x7b, 0x2e, 0x8f,
                    0xc7, 0xa6, 0xcd, 0x31, 0xfc, 0xad, 0x95, 0xc4, 0x8f, 0xc2, 0x8b, 0xe7, 0x60,
                    0x03, 0x53, 0xeb, 0xe1, 0x6d, 0x44,
                ])
            );
            assert_eq!(
                subkey3,
                SubKey([
                    0x91, 0x66, 0x81, 0x88, 0xb1, 0x6d, 0xc0, 0xee, 0x32, 0x17, 0xa3, 0xe2, 0xa8,
                    0x6a, 0x97, 0xb5, 0x42, 0xba, 0x13, 0x3b, 0xcd, 0x8e, 0x30, 0x7f, 0xf1, 0xb1,
                    0x77, 0x64, 0xd0, 0xe5, 0x7a, 0x8f,
                ])
            );
        }
        {
            let key = Key([1u8; KEYBYTES]);
            let ctx = [2u8; CONTEXTBYTES];
            let subkey1 = derive_from_key(1, ctx, &key).unwrap();
            let subkey2 = derive_from_key(2, ctx, &key).unwrap();
            let subkey3 = derive_from_key(3, ctx, &key).unwrap();

            assert_eq!(
                subkey1,
                SubKey([
                    0x3b, 0xf2, 0xde, 0xf5, 0x76, 0xf5, 0xd3, 0xfc, 0xa3, 0x6a, 0x32, 0x85, 0x80,
                    0x96, 0x80, 0xdc, 0xc8, 0x60, 0x6f, 0x54, 0xbd, 0x79, 0xd5, 0x76, 0x6b, 0x47,
                    0xc5, 0x74, 0xdd, 0x05, 0x8a, 0xfb,
                ])
            );
            assert_eq!(
                subkey2,
                SubKey([
                    0x3d, 0x0d, 0x54, 0xb1, 0x54, 0xcc, 0x5f, 0x26, 0xe0, 0x66, 0x71, 0xc4, 0x9b,
                    0xc4, 0x3f, 0x61, 0x66, 0xac, 0xef, 0xe9, 0x0b, 0xf4, 0x71, 0x7b, 0xa1, 0x6f,
                    0xe4, 0x0c, 0xfa, 0x9d, 0x7b, 0x40,
                ])
            );
            assert_eq!(
                subkey3,
                SubKey([
                    0x4e, 0x00, 0x62, 0x56, 0x9a, 0xb1, 0x96, 0xa3, 0x2e, 0xfe, 0x2d, 0xa4, 0x09,
                    0xbd, 0x9b, 0x5b, 0x9d, 0x05, 0x28, 0x05, 0xd8, 0xcb, 0xb2, 0x7a, 0x6f, 0xa4,
                    0xca, 0xfb, 0xaf, 0x6f, 0xd5, 0xc7,
                ])
            );
        }
    }
}
