//! Cryptographic random number generation.

use ffi;
use libc::c_void;

/// `randombytes()` randomly generates size bytes of data.
///
/// THREAD SAFETY: `randombytes()` is thread-safe provided that you have
/// called `rust_sodium::init()` once before using any other function
/// from `rust_sodium`.
pub fn randombytes(size: usize) -> Vec<u8> {
    unsafe {
        let mut buf = vec![0u8; size];
        let pbuf = buf.as_mut_ptr() as *mut c_void;
        ffi::randombytes_buf(pbuf, size);
        buf
    }
}

/// `randombytes_into()` fills a buffer `buf` with random data.
///
/// THREAD SAFETY: `randombytes_into()` is thread-safe provided that you have
/// called `rust_sodium::init()` once before using any other function
/// from `rust_sodium`.
pub fn randombytes_into(buf: &mut [u8]) {
    unsafe {
        ffi::randombytes_buf(buf.as_mut_ptr() as *mut c_void, buf.len());
    }
}
