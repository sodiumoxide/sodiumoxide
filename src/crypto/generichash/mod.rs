//! `GenericHash`.
//!
use ffi::{crypto_generichash_final, crypto_generichash_init,
          crypto_generichash_statebytes, crypto_generichash_update,
          crypto_generichash_BYTES_MAX, crypto_generichash_BYTES_MIN,
          crypto_generichash_KEYBYTES_MAX, crypto_generichash_KEYBYTES_MIN};

use libc::c_ulonglong;
use std::ptr;

mod digest;
pub use self::digest::Digest;

/// Minimium of allowed bytes in a `Digest`
pub const DIGEST_MIN: usize = crypto_generichash_BYTES_MIN;

/// Maximum of allowed bytes in a `Digest`
pub const DIGEST_MAX: usize = crypto_generichash_BYTES_MAX;

/// Minimium of allowed bytes in a key
pub const KEY_MIN: usize = crypto_generichash_KEYBYTES_MIN;

/// Maximum of allowed bytes in a key
pub const KEY_MAX: usize = crypto_generichash_KEYBYTES_MAX;

/// `State` contains the state for multi-part (streaming) hash computations. This allows the caller
/// to process a message as a sequence of multiple chunks.
pub struct State {
    out_len: usize,
    state: Vec<u8>,
}

impl State {
    /// `new` constructs and initializes a new `State` with the given parameters.
    ///
    /// `out_len` specifies the resulting hash size.
    /// Only values in the interval [`DIGEST_MIN`, `DIGEST_MAX`] are allowed.
    ///
    /// `key` is an optional parameter, which when given,
    /// a custom key can be used for the computation of the hash.
    /// The size of the key must be in the interval [`KEY_MIN`, `KEY_MAX`].
    pub fn new(out_len: usize, key: Option<&[u8]>) -> Option<State> {
        if out_len < DIGEST_MIN || out_len > DIGEST_MAX {
            return None;
        }

        if let Some(key) = key {
            let len = key.len();
            if len < KEY_MIN || len > KEY_MAX {
                return None;
            }
        }

        let mut state = Vec::<u8>::new();
        let result = unsafe {
            state.reserve_exact(crypto_generichash_statebytes());
            let state_ptr = state.as_mut_slice().as_mut_ptr() as *mut _;
            if let Some(key) = key {
                crypto_generichash_init(
                    state_ptr,
                    key.as_ptr(),
                    key.len(),
                    out_len,
                )
            } else {
                crypto_generichash_init(state_ptr, ptr::null(), 0, out_len)
            }
        };

        if result == 0 {
            Some(State {
                out_len: out_len,
                state: state,
            })
        } else {
            None
        }
    }

    /// `update` updates the `State` with `data`. `update` can be called multiple times in order
    /// to compute the hash from sequential chunks of the message.
    pub fn update(&mut self, data: &[u8]) {
        unsafe {
            let state_ptr = self.state.as_mut_slice().as_mut_ptr() as *mut _;
            crypto_generichash_update(
                state_ptr,
                data.as_ptr(),
                data.len() as c_ulonglong,
            );
        }
    }

    /// `finalize` finalizes the state and returns the digest value. `finalize` consumes the
    /// `State` so that it cannot be accidentally reused.
    pub fn finalize(mut self) -> Digest {
        let state_ptr = self.state.as_mut_slice().as_mut_ptr() as *mut _;
        let mut result = Digest {
            len: self.out_len,
            data: [0u8; crypto_generichash_BYTES_MAX],
        };
        unsafe {
            crypto_generichash_final(
                state_ptr,
                result.data.as_mut_ptr(),
                result.len,
            );
        }
        result
    }
}
