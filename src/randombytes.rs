//! Cryptographic random number generation.
use ffi;
use std::iter::repeat;

/// `randombytes()` randomly generates size bytes of data.
///
/// THREAD SAFETY: `randombytes()` is thread-safe provided that you have
/// called `sodiumoxide::init()` once before using any other function
/// from sodiumoxide.
pub fn randombytes(size: usize) -> Vec<u8> {
    unsafe {
        let mut buf: Vec<u8> = repeat(0u8).take(size).collect();
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

/// `randombytes_uniform()` returns an unpredictable value between 0 and
/// `upper_bound` (excluded). It does its best to guarantee a uniform
/// distribution of the possible output values.
///
/// THREAD SAFETY: `randombytes_uniform()` is thread-safe provided that you
/// have called `sodiumoxide::init()` once before using any other function
/// from sodiumoxide.
pub fn randombytes_uniform(upper_bound: u32) -> u32 {
    unsafe {
        ffi::randombytes_uniform(upper_bound)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_randombytes_uniform_lt1000() {
        for _ in 0..100 {
            let random = randombytes_uniform(1000);
            assert!(random < 1000);
        }
    }

    #[test]
    fn test_randombytes_uniform_lt3() {
        for _ in 0..100 {
            let random = randombytes_uniform(3);
            assert!(random < 3);
        }
    }

}
