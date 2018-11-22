//! Libsodium utility functions

use ffi;
use libc::c_void;

/// `memzero()` tries to effectively zero out the data in `x` even if
/// optimizations are being applied to the code.
pub fn memzero(x: &mut [u8]) {
    unsafe {
        ffi::sodium_memzero(x.as_mut_ptr() as *mut c_void, x.len());
    }
}

/// `memcmp()` returns true if `x[0]`, `x[1]`, ..., `x[len-1]` are the
/// same as `y[0]`, `y[1]`, ..., `y[len-1]`. Otherwise it returns `false`.
///
/// This function is safe to use for secrets `x[0]`, `x[1]`, ..., `x[len-1]`,
/// `y[0]`, `y[1]`, ..., `y[len-1]`. The time taken by `memcmp` is independent
/// of the contents of `x[0]`, `x[1]`, ..., `x[len-1]`, `y[0]`, `y[1]`, ..., `y[len-1]`.
/// In contrast, the standard C comparison function `memcmp(x,y,len)` takes time
/// that depends on the longest matching prefix of `x` and `y`, often allowing easy
/// timing attacks.
pub fn memcmp(x: &[u8], y: &[u8]) -> bool {
    if x.len() != y.len() {
        return false;
    }
    unsafe {
        ffi::sodium_memcmp(
            x.as_ptr() as *mut c_void,
            y.as_ptr() as *mut c_void,
            x.len(),
        ) == 0
    }
}

/// `increment_le()` treats `x` as an unsigned little-endian number and increments it.
///
/// WARNING: this method does not check for arithmetic overflow. When used for incrementing
/// nonces it is the callers responsibility to ensure that any given nonce value
/// is only used once.
/// If the caller does not do that the cryptographic primitives in `rust_sodium`
/// will not uphold any security guarantees (i.e. they will break)
pub fn increment_le(x: &mut [u8]) {
    unsafe {
        ffi::sodium_increment(x.as_mut_ptr(), x.len());
    }
}

/// Tries to add padding to a sequence of bytes.
/// If the block size is zero, or the padded buffer's length
/// could overflow `usize`, this function returns `Err`.
/// Otherwise, it returns `Ok` wrapping the padded byte array.
pub fn pad(mut buf: Vec<u8>, blocksize: usize) -> Result<Vec<u8>, ()> {
    let unpadded_buflen = buf.len();
    let max_buflen = unpadded_buflen + blocksize;
    let mut padded_buflen = 0;

    if max_buflen <= unpadded_buflen {
        return Err(());
    }

    // extend with zeroes
    buf.resize(max_buflen, 0);

    let error = unsafe {
        ffi::sodium_pad(
            &mut padded_buflen,
            buf.as_mut_ptr(),
            unpadded_buflen,
            blocksize,
            max_buflen,
        )
    };

    assert!(error == 0, "sodium_pad: unsatisfied precondition?!");
    assert!(padded_buflen <= max_buflen, "math is broken?!");
    assert!(padded_buflen > unpadded_buflen, "no padding added?!");

    buf.truncate(padded_buflen);

    Ok(buf)
}

/// Attempts to remove padding from a byte sequence created via `pad()`.
/// If the padding is nonexistent, invalid, or the block size does not
/// match the `blocksize` argument of `pad()`, this returns `Err`.
pub fn unpad(buf: &[u8], blocksize: usize) -> Result<&[u8], ()> {
    let padded_buflen = buf.len();
    let mut unpadded_buflen = 0;

    let error =
        unsafe { ffi::sodium_unpad(&mut unpadded_buflen, buf.as_ptr(), padded_buflen, blocksize) };

    if error != 0 {
        return Err(());
    }

    assert!(unpadded_buflen < padded_buflen, "no padding?!");

    Ok(&buf[..unpadded_buflen])
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_memcmp() {
        use randombytes::randombytes;

        unwrap!(::init());
        for i in 0usize..256 {
            let x = randombytes(i);
            assert!(memcmp(&x, &x));
            let mut y = x.clone();
            assert!(memcmp(&x, &y));
            y.push(0);
            assert!(!memcmp(&x, &y));
            assert!(!memcmp(&y, &x));

            y = randombytes(i);
            if x == y {
                assert!(memcmp(&x, &y))
            } else {
                assert!(!memcmp(&x, &y))
            }
        }
    }

    #[test]
    fn test_increment_le_zero() {
        unwrap!(::init());
        for i in 1usize..256 {
            let mut x = vec![0u8; i];
            increment_le(&mut x);
            assert!(!x.iter().all(|x| *x == 0));
            let mut y = vec![0u8; i];
            y[0] += 1;
            assert_eq!(x, y);
        }
    }

    #[test]
    fn test_increment_le_vectors() {
        unwrap!(::init());
        let mut x = [255, 2, 3, 4, 5];
        let y = [0, 3, 3, 4, 5];
        increment_le(&mut x);
        assert!(!x.iter().all(|x| *x == 0));
        assert_eq!(x, y);
        let mut x = [255, 255, 3, 4, 5];
        let y = [0, 0, 4, 4, 5];
        increment_le(&mut x);
        assert!(!x.iter().all(|x| *x == 0));
        assert_eq!(x, y);
        let mut x = [255, 255, 255, 4, 5];
        let y = [0, 0, 0, 5, 5];
        increment_le(&mut x);
        assert!(!x.iter().all(|x| *x == 0));
        assert_eq!(x, y);
        let mut x = [255, 255, 255, 255, 5];
        let y = [0, 0, 0, 0, 6];
        increment_le(&mut x);
        assert!(!x.iter().all(|x| *x == 0));
        assert_eq!(x, y);
        let mut x = [255, 255, 255, 255, 255];
        let y = [0, 0, 0, 0, 0];
        increment_le(&mut x);
        assert!(x.iter().all(|x| *x == 0));
        assert_eq!(x, y);
    }

    #[test]
    fn test_increment_le_overflow() {
        unwrap!(::init());
        for i in 1usize..256 {
            let mut x = vec![255u8; i];
            increment_le(&mut x);
            assert!(x.iter().all(|xi| *xi == 0));
        }
    }

    #[test]
    fn test_padding_not_multiple_of_blocksize() {
        unwrap!(::init());
        let v = vec![1, 2, 3, 4, 5, 6, 7];
        let p = unwrap!(pad(v.clone(), 5));
        let u = unwrap!(unpad(&p, 5));

        assert!(p.len() == 10);
        assert!(u == &v[..]);
    }

    #[test]
    fn test_padding_multiple_of_blocksize() {
        unwrap!(::init());
        let v = vec![1, 2, 3, 4, 5, 6];
        let p = unwrap!(pad(v.clone(), 3));
        let u = unwrap!(unpad(&p, 3));

        assert!(p.len() == 9);
        assert!(u == &v[..]);
    }

    #[test]
    fn test_padding_not_multiple_of_blocksize_pow2() {
        unwrap!(::init());
        let v = vec![1, 2, 3, 4, 5, 6, 7];
        let p = unwrap!(pad(v.clone(), 4));
        let u = unwrap!(unpad(&p, 4));

        assert!(p.len() == 8);
        assert!(u == &v[..]);
    }

    #[test]
    fn test_padding_multiple_of_blocksize_pow2() {
        unwrap!(::init());
        let v = vec![1, 2, 3, 4, 5, 6, 7, 8];
        let p = unwrap!(pad(v.clone(), 4));
        let u = unwrap!(unpad(&p, 4));

        assert!(p.len() == 12);
        assert!(u == &v[..]);
    }

    #[test]
    fn test_padding_invalid_block_size() {
        unwrap!(::init());
        // invalid block size
        unwrap_err!(pad(Vec::new(), 0));
        let v = vec![0x80];
        unwrap_err!(unpad(&v, 0));

        // mismatching block size
        let v = unwrap!(pad(Vec::new(), 8));
        unwrap_err!(unpad(&v, 4));
    }

    #[test]
    fn test_padding_invalid_padded_size() {
        unwrap!(::init());
        // An empty array couldn't possibly have been created by `pad()`.
        unwrap_err!(unpad(&[], 1));

        // Padded scheme is of incorrect length (not a multiple of block size)
        let mut v = unwrap!(pad(vec![42], 1337));
        let _ = v.pop();
        unwrap_err!(unpad(&v, 1337));
    }

    #[test]
    fn test_padding_invalid_padded_data() {
        unwrap!(::init());
        // A trailing padding byte is incorrect
        let mut v = unwrap!(pad(vec![42], 128));
        *v.last_mut().expect("non-empty") = 99;
        unwrap_err!(unpad(&v, 128));
    }
}
