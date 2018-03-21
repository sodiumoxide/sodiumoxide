//! `GenericHash`.
//!
#[cfg(not(feature = "std"))] use prelude::Vec;

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

#[cfg(test)]
mod test {
    use super::*;
    #[cfg(not(feature = "std"))]
    use prelude::*;

    #[test]
    fn test_vector_1() {
        // hash of empty string
        let x = [];
        let h_expected = [
            0x0e, 0x57, 0x51, 0xc0, 0x26, 0xe5, 0x43, 0xb2, 0xe8, 0xab, 0x2e,
            0xb0, 0x60, 0x99, 0xda, 0xa1, 0xd1, 0xe5, 0xdf, 0x47, 0x77, 0x8f,
            0x77, 0x87, 0xfa, 0xab, 0x45, 0xcd, 0xf1, 0x2f, 0xe3, 0xa8,
        ];
        let mut hasher = State::new(32, None).unwrap();
        hasher.update(&x);
        let h = hasher.finalize();
        assert!(h.as_ref() == h_expected);
    }

    #[test]
    fn test_vector_2() {
        // The quick brown fox jumps over the lazy dog
        let x = [
            0x54, 0x68, 0x65, 0x20, 0x71, 0x75, 0x69, 0x63, 0x6b, 0x20, 0x62,
            0x72, 0x6f, 0x77, 0x6e, 0x20, 0x66, 0x6f, 0x78, 0x20, 0x6a, 0x75,
            0x6d, 0x70, 0x73, 0x20, 0x6f, 0x76, 0x65, 0x72, 0x20, 0x74, 0x68,
            0x65, 0x20, 0x6c, 0x61, 0x7a, 0x79, 0x20, 0x64, 0x6f, 0x67,
        ];
        let h_expected = [
            0x01, 0x71, 0x8c, 0xec, 0x35, 0xcd, 0x3d, 0x79, 0x6d, 0xd0, 0x00,
            0x20, 0xe0, 0xbf, 0xec, 0xb4, 0x73, 0xad, 0x23, 0x45, 0x7d, 0x06,
            0x3b, 0x75, 0xef, 0xf2, 0x9c, 0x0f, 0xfa, 0x2e, 0x58, 0xa9,
        ];
        let mut hasher = State::new(32, None).unwrap();
        hasher.update(&x);
        let h = hasher.finalize();
        assert!(h.as_ref() == h_expected);
    }

    #[test]
    fn test_blake2b_vectors() {
        use rustc_serialize::hex::FromHex;
        use std::fs::File;
        use std::io::{BufRead, BufReader};

        let mut r =
            BufReader::new(File::open("testvectors/blake2b-kat.txt").unwrap());
        let mut line = String::new();

        loop {
            let msg = {
                line.clear();
                if let Err(_) = r.read_line(&mut line) {
                    break;
                }

                match line.len() {
                    0 => break,
                    1...3 => continue,
                    _ => {}
                }

                assert!(line.starts_with("in:"));
                line[3..].trim().from_hex().unwrap()
            };

            let key = {
                line.clear();
                r.read_line(&mut line).unwrap();
                assert!(line.starts_with("key:"));
                line[4..].trim().from_hex().unwrap()
            };

            let expected_hash = {
                line.clear();
                r.read_line(&mut line).unwrap();
                assert!(line.starts_with("hash:"));
                line[5..].from_hex().unwrap()
            };

            let mut hasher = State::new(64, Some(&key)).unwrap();
            hasher.update(&msg);

            let result_hash = hasher.finalize();
            assert!(result_hash.as_ref() == expected_hash.as_slice());
        }
    }
}
