//! Constant-time comparison of fixed-size vecs
use ffi;

/// `verify_16()` returns `true` if `x[0]`, `x[1]`, ..., `x[15]` are the
/// same as `y[0]`, `y[1]`, ..., `y[15]`. Otherwise it returns `false`.
///
/// This function is safe to use for secrets `x[0]`, `x[1]`, ..., `x[15]`,
/// `y[0]`, `y[1]`, ..., `y[15]`. The time taken by `verify_16` is independent
/// of the contents of `x[0]`, `x[1]`, ..., `x[15]`, `y[0]`, `y[1]`, ..., `y[15]`.
/// In contrast, the standard C comparison function `memcmp(x,y,16)` takes time
/// that depends on the longest matching prefix of `x` and `y`, often allowing easy
/// timing attacks.
pub fn verify_16(x: &[u8; 16], y: &[u8; 16]) -> bool {
    unsafe {
        ffi::crypto_verify_16(x.as_ptr(), y.as_ptr()) == 0
    }
}

/// `verify_32()` returns true if `x[0]`, `x[1]`, ..., `x[31]` are the
/// same as `y[0]`, `y[1]`, ..., `y[31]`. Otherwise it returns `false`.
///
/// This function is safe to use for secrets `x[0]`, `x[1]`, ..., `x[31]`,
/// `y[0]`, `y[1]`, ..., `y[31]`. The time taken by `verify_32` is independent
/// of the contents of `x[0]`, `x[1]`, ..., `x[31]`, `y[0]`, `y[1]`, ..., `y[31]`.
/// In contrast, the standard C comparison function `memcmp(x,y,32)` takes time
/// that depends on the longest matching prefix of `x` and `y`, often allowing easy
/// timing attacks.
pub fn verify_32(x: &[u8; 32], y: &[u8; 32]) -> bool {
    unsafe {
        ffi::crypto_verify_32(x.as_ptr(), y.as_ptr()) == 0
    }
}

/// `verify_64()` returns true if `x[0]`, `x[1]`, ..., `x[63]` are the
/// same as `y[0]`, `y[1]`, ..., `y[63]`. Otherwise it returns `false`.
///
/// This function is safe to use for secrets `x[0]`, `x[1]`, ..., `x[63]`,
/// `y[0]`, `y[1]`, ..., `y[63]`. The time taken by `verify_64` is independent
/// of the contents of `x[0]`, `x[1]`, ..., `x[63]`, `y[0]`, `y[1]`, ..., `y[63]`.
/// In contrast, the standard C comparison function `memcmp(x,y,64)` takes time
/// that depends on the longest matching prefix of `x` and `y`, often allowing easy
/// timing attacks.
pub fn verify_64(x: &[u8; 64], y: &[u8; 64]) -> bool {
    unsafe {
        ffi::crypto_verify_64(x.as_ptr(), y.as_ptr()) == 0
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_verify_16() {
        use randombytes::randombytes_into;

        for _ in 0usize..256 {
            let mut x = [0; 16];
            let mut y = [0; 16];
            assert!(verify_16(&x, &y));
            randombytes_into(&mut x);
            randombytes_into(&mut y);
            if x == y {
                assert!(verify_16(&x, &y))
            } else {
                assert!(!verify_16(&x, &y))
            }
        }
    }

    quickcheck! {
        fn qc_verify_16(diff: Vec<usize>) -> bool {
            use randombytes::randombytes_into;

            ({ // no diff
                let mut x = [0; 16];
                let mut y = [0; 16];

                assert!(verify_16(&x, &y));
                assert!(verify_16(&y, &x));

                randombytes_into(&mut x);
                y = x;

                verify_16(&x, &y) && verify_16(&y, &x)
            })
                &&
                ({ // add diff according to provided vector
                    let mut x = [0; 16];
                    let mut y = [0; 16];

                    assert!(verify_16(&x, &y));
                    assert!(verify_16(&y, &x));

                    randombytes_into(&mut x);
                    y = x;

                    for i in &diff[..] {
                        let i = i % 16;
                        y[i] = y[i].wrapping_add(1);
                    }

                    if x == y {
                        verify_16(&x, &y) && verify_16(&y, &x)
                    } else {
                        !verify_16(&x, &y) && !verify_16(&y, &x)
                    }
                })
        }
    }

    #[test]
    fn test_verify_32() {
        use randombytes::randombytes_into;

        for _ in 0usize..256 {
            let mut x = [0; 32];
            let mut y = [0; 32];
            assert!(verify_32(&x, &y));
            randombytes_into(&mut x);
            randombytes_into(&mut y);
            if x == y {
                assert!(verify_32(&x, &y))
            } else {
                assert!(!verify_32(&x, &y))
            }
        }
    }

    quickcheck! {
        fn qc_verify_32(diff: Vec<usize>) -> bool {
            use randombytes::randombytes_into;

            ({ // no diff
                let mut x = [0; 32];
                let mut y = [0; 32];

                assert!(verify_32(&x, &y));
                assert!(verify_32(&y, &x));

                randombytes_into(&mut x);
                y = x;

                verify_32(&x, &y) && verify_32(&y, &x)
            })
                &&
                ({ // add diff according to provided vector
                    let mut x = [0; 32];
                    let mut y = [0; 32];

                    assert!(verify_32(&x, &y));
                    assert!(verify_32(&y, &x));

                    randombytes_into(&mut x);
                    y = x;

                    for i in &diff[..] {
                        let i = i % 32;
                        y[i] = y[i].wrapping_add(1);
                    }

                    if x == y {
                        verify_32(&x, &y) && verify_32(&y, &x)
                    } else {
                        !verify_32(&x, &y) && !verify_32(&y, &x)
                    }
                })
        }
    }

    #[test]
    fn test_verify_64() {
        use randombytes::randombytes_into;

        for _ in 0usize..256 {
            let mut x = [0; 64];
            let mut y = [0; 64];
            assert!(verify_64(&x, &y));
            randombytes_into(&mut x);
            randombytes_into(&mut y);
            if x[..] == y[..] {
                assert!(verify_64(&x, &y))
            } else {
                assert!(!verify_64(&x, &y))
            }
        }
    }

    quickcheck! {
        fn qc_verify_64(diff: Vec<usize>) -> bool {
            use randombytes::randombytes_into;

            ({ // no diff
                let mut x = [0; 64];
                let mut y = [0; 64];

                assert!(verify_64(&x, &y));
                assert!(verify_64(&y, &x));

                randombytes_into(&mut x);
                y = x;

                verify_64(&x, &y) && verify_64(&y, &x)
            })
                &&
                ({ // add diff according to provided vector
                    let mut x = [0; 64];
                    let mut y = [0; 64];

                    assert!(verify_64(&x, &y));
                    assert!(verify_64(&y, &x));

                    randombytes_into(&mut x);
                    y = x;

                    for i in &diff[..] {
                        let i = i % 64;
                        y[i] = y[i].wrapping_add(1);
                    }

                    let mut same = true;
                    for i in 0..64 {
                        if x[i] != y[i] {
                            same = false;
                        }
                    }

                    if same {
                        verify_64(&x, &y) && verify_64(&y, &x)
                    } else {
                        !verify_64(&x, &y) && !verify_64(&y, &x)
                    }
                })
        }
    }
}
