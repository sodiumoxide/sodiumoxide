//! Libsodium utility functions
use ffi;

/// `safe_memcmp()` returns true if `x[0]`, `x[1]`, ..., `x[len-1]` are the
/// same as `y[0]`, `y[1]`, ..., `y[len-1]`. Otherwise it returns `false`.
///
/// This function is safe to use for secrets `x[0]`, `x[1]`, ..., `x[len-1]`,
/// `y[0]`, `y[1]`, ..., `y[len-1]`. The time taken by `safe_memcmp` is independent
/// of the contents of `x[0]`, `x[1]`, ..., `x[len-1]`, `y[0]`, `y[1]`, ..., `y[len-1]`.
/// In contrast, the standard C comparison function `memcmp(x,y,len)` takes time
/// that depends on the longest matching prefix of `x` and `y`, often allowing easy
/// timing attacks.
pub fn safe_memcmp(x: &[u8], y: &[u8]) -> bool {
    if x.len() != y.len() {
        return false
    }
    unsafe {
        ffi::sodium_memcmp(x.as_ptr(), y.as_ptr(), x.len()) == 0
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_safe_memcmp() {
        use randombytes::randombytes;

        for i in (0usize..256) {
            let x = randombytes(i);
            assert!(safe_memcmp(&x, &x));
            let mut y = x.clone();
            assert!(safe_memcmp(&x, &y));
            y.push(0);
            assert!(!safe_memcmp(&x, &y));
            assert!(!safe_memcmp(&y, &x));

            y = randombytes(i);
            if x == y {
                assert!(safe_memcmp(&x, &y))
            } else {
                assert!(!safe_memcmp(&x, &y))
            }
        }
    }
}
