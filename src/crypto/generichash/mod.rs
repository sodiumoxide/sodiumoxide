use ffi::{crypto_generichash_final, crypto_generichash_init,
          crypto_generichash_statebytes, crypto_generichash_update,
          crypto_generichash_BYTES_MAX, crypto_generichash_BYTES_MIN,
          crypto_generichash_KEYBYTES_MAX, crypto_generichash_KEYBYTES_MIN};

use libc::c_ulonglong;
use std::ptr;

mod digest;
pub use self::digest::Digest;

pub struct State {
    out_len: usize,
    state: Vec<u8>,
}

impl State {
    fn new(out_len: usize, key: Option<&[u8]>) -> Option<State> {
        if out_len < crypto_generichash_BYTES_MIN
            || out_len > crypto_generichash_BYTES_MAX
        {
            return None;
        }

        if let Some(key) = key {
            let len = key.len();
            if len < crypto_generichash_KEYBYTES_MIN
                || len > crypto_generichash_KEYBYTES_MAX
            {
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
