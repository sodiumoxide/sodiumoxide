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
    /// `Context` for key derivation.
    public Context(CONTEXTBYTES);
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
pub fn derive_from_key(subkey_id: u64, ctx: &Context, key: &Key) -> Result<SubKey, ()> {
    unsafe {
        let mut subkey = SubKey([0u8; SUBKEYBYTES]);
        let r = ffi::crypto_kdf_blake2b_derive_from_key(
            subkey.0.as_mut_ptr(),
            SUBKEYBYTES,
            subkey_id,
            ctx.0.as_ptr() as *mut i8,
            key.0.as_ptr(),
        );
        if r != 0 {
            Err(())
        } else {
            Ok(subkey)
        }
    }
}
