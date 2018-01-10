#[cfg(not(feature = "std"))] use prelude::*;
use ffi;
use libc::c_ulonglong;
use std::iter::repeat;

use super::SIGNATUREBYTES;
use super::ed25519::{SecretKey,Signature};

struct crypto_sign_state;
#[link(name="sodium")]
extern {
    fn sign_init(x: *mut crypto_sign_state);
}

struct MultipartSignature {
    state: crypto_sign_state
}

impl MultipartSignature {
    pub fn new() -> MultipartSignature {
        let mut state: crypto_sign_state;
        unsafe {
            ffi::crypto_sign_init(&mut state);
        }
        MultipartSignature {
            state: state
        }
    }

    pub fn update(&mut self, data: &[u8]) -> &mut MultipartSignature {
        unsafe {
            ffi::crypto_sign_update(&mut self.state, data.as_ptr(), data.len() as c_ulonglong);
        }
        self
    }

    pub fn final_create(mut self, &SecretKey(ref sk): &SecretKey) -> Signature {
        unsafe {
            let mut sig = [0u8; SIGNATUREBYTES];
            let mut siglen: c_ulonglong = 0;
            ffi::crypto_sign_final_create(
                &mut sig,
                &mut siglen,
                sk
            );
            assert_eq!(siglen, SIGNATUREBYTES as c_ulonglong);
            Signature(sig)
        }
    }
}

