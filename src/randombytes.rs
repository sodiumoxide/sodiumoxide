/*! Cryptographic random number generation
*/
use ffi;
use libc::size_t;

/**
 * `randombytes()` randomly generates size bytes of data.
 *
 * THREAD SAFETY: `randombytes()` is thread-safe provided that you have
 * called `sodiumoxide::init()` once before using any other function
 * from sodiumoxide.
 */
pub fn randombytes(size: uint) -> Vec<u8> {
    unsafe {
        let mut buf = Vec::from_elem(size, 0u8);
        let pbuf = buf.as_mut_ptr();
        ffi::randombytes_buf(pbuf, size as size_t);
        buf
    }
}

/**
 * `randombytes_into()` fills a buffer `buf` with random data.
 *
 * THREAD SAFETY: `randombytes_into()` is thread-safe provided that you have
 * called `sodiumoxide::init()` once before using any other function
 * from sodiumoxide.
 */
pub fn randombytes_into(buf: &mut [u8]) {
    unsafe {
        ffi::randombytes_buf(buf.as_mut_ptr(), buf.len() as size_t);
    }
}
