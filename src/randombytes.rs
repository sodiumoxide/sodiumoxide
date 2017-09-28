//! Cryptographic random number generation.
#[cfg(not(feature = "std"))] use prelude::*;
use ffi;

/// `randombytes()` randomly generates size bytes of data.
///
/// THREAD SAFETY: `randombytes()` is thread-safe provided that you have
/// called `sodiumoxide::init()` once before using any other function
/// from sodiumoxide.
pub fn randombytes(size: usize) -> Vec<u8> {
    unsafe {
        let mut buf = vec![0u8; size];
        let pbuf = buf.as_mut_ptr();
        ffi::randombytes_buf(pbuf, size);
        buf
    }
}

/// `randombytes_into()` fills a buffer `buf` with random data.
///
/// THREAD SAFETY: `randombytes_into()` is thread-safe provided that you have
/// called `sodiumoxide::init()` once before using any other function
/// from sodiumoxide.
pub fn randombytes_into(buf: &mut [u8]) {
    unsafe {
        ffi::randombytes_buf(buf.as_mut_ptr(), buf.len());
    }
}
