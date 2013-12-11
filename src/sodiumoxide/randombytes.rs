/*! Cryptographic random number generation
*/
use std::libc::size_t;
use std::vec::from_elem;
use std::vec::raw::to_mut_ptr;

#[link(name = "sodium")]
extern {
    fn randombytes_buf(buf: *mut u8,
                       size: size_t);
}

/**
 * `randombytes()` randomly generates size bytes of data.
 *
 * THREAD SAFETY: `randombytes()` is thread-safe provided that you have
 * called `sodiumoxide::init()` once before using any other function
 * from sodiumoxide.
 */
#[fixed_stack_segment]
pub fn randombytes(size: uint) -> ~[u8] {
    unsafe {
        let mut buf = from_elem(size, 0u8);
        let pbuf = to_mut_ptr(buf);
        randombytes_buf(pbuf, size as size_t);
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
#[fixed_stack_segment]
pub fn randombytes_into(buf: &mut [u8]) {
    unsafe {
        randombytes_buf(to_mut_ptr(buf), buf.len() as size_t);
    }
}
