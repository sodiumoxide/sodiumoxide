//! Libsodium utility functions
use ffi;

use std::ptr::null;

/// `memzero()` tries to effectively zero out the data in `x` even if
/// optimizations are being applied to the code.
pub fn memzero(x: &mut [u8]) {
    unsafe {
        ffi::sodium_memzero(x.as_mut_ptr() as *mut _, x.len());
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
            x.as_ptr() as *const _,
            y.as_ptr() as *const _,
            x.len(),
        ) == 0
    }
}

/// `increment_le()` treats `x` as an unsigned little-endian number and increments it in
/// constant time.
///
/// WARNING: this method does not check for arithmetic overflow. When used for incrementing
/// nonces it is the caller's responsibility to ensure that any given nonce value
/// is used only once.
/// If the caller does not do that the cryptographic primitives in sodiumoxide
/// will not uphold any security guarantees (i.e. they may break)
pub fn increment_le(x: &mut [u8]) {
    unsafe {
        ffi::sodium_increment(x.as_mut_ptr(), x.len());
    }
}

/// `add_le()` treats `x` and `y` as unsigned little-endian numbers and adds `y` to `x`
/// modulo 2^(8*len) in constant time.
///
/// `add_le()` will return Err<()> if the length of `x` is not equal to the length of `y`.
///
/// WARNING: When used for incrementing nonces it is the caller's responsibility to ensure
/// that any given nonce value is used only once.
/// If the caller does not do that the cryptographic primitives in sodiumoxide
/// will not uphold any security guarantees (i.e. they may break)
pub fn add_le(x: &mut [u8], y: &[u8]) -> Result<(), ()> {
    if x.len() == y.len() {
        unsafe {
                ffi::sodium_add(x.as_mut_ptr(), y.as_ptr(), x.len());
        }
        Ok(())
    } else  {
        Err(())
    }
}

/// `bin2hex()` takes raw bytes as `bin`, converts it to hexadecimal and puts the result in `hex`.
/// `hex` contains a nul byte (\0) terminator
/// `bin2hex()` will return Err<()> if length of `hex` is not sufficient to hold the hex representation of `bin`.
/// Refer docs at https://download.libsodium.org/doc/helpers#hexadecimal-encoding-decoding
pub fn bin2hex(hex: &mut [u8], bin: &[u8]) -> Result<(), ()> {
    if hex.len() <= 2*bin.len() {
        return Err(());
    }
    unsafe {
        ffi::sodium_bin2hex(hex.as_mut_ptr() as *mut _, 2*bin.len()+1, bin.as_ptr(), bin.len());
    }
    Ok(())
}

/// `hex2bin()` takes bytes of a hexadecimal string in `hex`, converts it to raw bytes and puts the result in `bin`
/// `ignore` is an optional parameter, taking a byte representation of a string to skip
/// `bin_len` is the length of raw bytes that `hex` was converted to.
/// `hex_end` is an optional parameter, if passed a pointer, it will be set to the address of the
/// first byte after the last valid parsed character.
/// Refer docs at https://download.libsodium.org/doc/helpers#hexadecimal-encoding-decoding
pub fn hex2bin(bin: &mut [u8], hex: &[u8], ignore: Option<&[u8]>, bin_len: &mut usize, hex_end: Option<&mut [u8]>) {
    let ignore = match ignore {
        Some(p) => p.as_ptr(),
        None => null()
    };
    let hex_end = match hex_end {
        Some(p) => p.as_mut_ptr(),
        None => null()
    };
    unsafe {
        ffi::sodium_hex2bin(bin.as_mut_ptr() as *mut _, bin.len(), hex.as_ptr() as *const _,
                            hex.len(), ignore as *const _, bin_len, hex_end  as *mut _);
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_memcmp() {
        use randombytes::randombytes;

        for i in 0..256 {
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
        for i in 1..256 {
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
        for i in 1..256 {
            let mut x = vec![255u8; i];
            increment_le(&mut x);
            assert!(x.iter().all(|xi| *xi == 0));
        }
    }

    #[test]
    fn test_add_le_zero() {
        for i in 1..256 {
            let mut x = vec!(0u8; i);
            let mut y = vec!(0u8; i);
            y[0] = 42;
            assert!(add_le(&mut x, &y).is_ok());
            assert!(!x.iter().all(|x| { *x == 0 }));
            assert_eq!(x, y);
        }
    }

    #[test]
    fn test_add_le_vectors() {
        let mut x = [255, 2, 3, 4, 5];
        let y = [42, 0, 0, 0, 0];
        let z = [41, 3, 3, 4, 5];
        assert!(add_le(&mut x, &y).is_ok());
        assert!(!x.iter().all(|x| { *x == 0 }));
        assert_eq!(x, z);
        let mut x = [255, 255, 3, 4, 5];
        let z = [41, 0, 4, 4, 5];
        assert!(add_le(&mut x, &y).is_ok());
        assert!(!x.iter().all(|x| { *x == 0 }));
        assert_eq!(x, z);
        let mut x = [255, 255, 255, 4, 5];
        let z = [41, 0, 0, 5, 5];
        assert!(add_le(&mut x, &y).is_ok());
        assert!(!x.iter().all(|x| { *x == 0 }));
        assert_eq!(x, z);
        let mut x = [255, 255, 255, 255, 5];
        let z = [41, 0, 0, 0, 6];
        assert!(add_le(&mut x, &y).is_ok());
        assert!(!x.iter().all(|x| { *x == 0 }));
        assert_eq!(x, z);
        let mut x = [255, 255, 255, 255, 255];
        let z = [41, 0, 0, 0, 0];
        assert!(add_le(&mut x, &y).is_ok());
        assert!(!x.iter().all(|x| { *x == 0 }));
        assert_eq!(x, z);
    }

    #[test]
    fn test_add_le_overflow() {
        for i in 1..256 {
            let mut x = vec!(255u8; i);
            let mut y = vec!(0u8; i);
            y[0] = 42;
            assert!(add_le(&mut x, &y).is_ok());
            assert!(!x.iter().all(|x| { *x == 0 }));
            y[0] -= 1;
            assert_eq!(x, y);
        }
    }

    #[test]
    fn test_add_le_different_lengths() {
        for i in 1..256 {
            let mut x = vec!(1u8; i);
            let y = vec!(42u8; i + 1);
            let z = vec!(42u8; i - 1);
            assert!(add_le(&mut x, &y).is_err());
            assert_eq!(x, vec!(1u8; i));
            assert!(add_le(&mut x, &z).is_err());
            assert_eq!(x, vec!(1u8; i));
        }
    }

    #[test]
    fn test_bin2hex() {
        use std::str;

        for (i, j) in vec![(0, "00\u{0}"), (1, "01\u{0}"), (10, "0a\u{0}"), (15, "0f\u{0}")] {
            let bytes: [u8; 1] = [i];
            let mut hex: [u8; 3] = [0; 3];
            bin2hex(&mut hex, &bytes).unwrap();
            assert_eq!(j, str::from_utf8(&hex).unwrap());
        }
    }

    #[test]
    fn test_hex2bin() {
        for (i, j) in vec![(0, "00\u{0}"), (1, "01\u{0}"), (10, "0a\u{0}"), (15, "0f\u{0}")] {
            let hex = j.as_bytes();
            let mut bytes: [u8; 1] = [0];
            let mut byte_size = 0;
            hex2bin(&mut bytes, &hex, None, &mut byte_size, None);
            assert_eq!(byte_size, 1);
            assert_eq!(vec![i], bytes.to_vec());
        }
    }

    #[test]
    fn test_hex2bin_ignore() {
        let mut bytes: [u8; 2] = [0, 0];
        let mut byte_size = 0;
        let ignore = ": ".as_bytes();
        let expected_bytes = vec![105, 252];
        for hex in vec!["69:FC".as_bytes(), "69 FC".as_bytes(), "69 : FC".as_bytes(), "69FC".as_bytes()] {
            hex2bin(&mut bytes, &hex, Some(ignore), &mut byte_size, None);
            assert_eq!(byte_size, 2);
            assert_eq!(expected_bytes, bytes.to_vec());
        }
    }

    #[test]
    fn test_bin2hex_and_hex2bin() {
        use randombytes::randombytes;
        use super::super::init;

        init().unwrap();

        for i in 1..257 {
            let bytes = randombytes(i);
            let mut hex: Vec<u8> = vec![0; 2*i+1];
            bin2hex(&mut hex, &bytes).unwrap();
            assert_eq!(hex.len(), 2*i+1);
            let mut new_bytes: Vec<u8> = vec![0; i];
            let mut byte_size = 0;
            hex2bin(&mut new_bytes, &hex, None, &mut byte_size, None);
            assert_eq!(byte_size, i);
            assert_eq!(&bytes, &new_bytes);
        }
    }
}
