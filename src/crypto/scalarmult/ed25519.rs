//! `crypto_scalarmult_curve25519` specified in
//! [Cryptography in `NaCl`](http://nacl.cr.yp.to/valid.html), Sections 2, 3, and 4.
//! This function is conjectured to be strong. For background see Bernstein,
//! "Curve25519: new Diffie-Hellman speed records," Lecture Notes in Computer
//! Science 3958 (2006), 207–228, <http://cr.yp.to/papers.html#curve25519>.
use ffi;

/// Number of bytes in a `GroupElement`.
pub const GROUPELEMENTBYTES: usize = ffi::crypto_scalarmult_ed25519_BYTES as usize;

/// Number of bytes in a `Scalar`.
pub const SCALARBYTES: usize = ffi::crypto_scalarmult_ed25519_SCALARBYTES as usize;

new_type! {
    /// `Scalar` value (integer in byte representation)
    secret Scalar(SCALARBYTES);
}

new_type! {
    /// `GroupElement`
    secret GroupElement(GROUPELEMENTBYTES);
}

/// `scalarmult()` multiplies a group element `p`
/// by an integer `n`. It returns the resulting group element `Ok(q)`.
/// If the the `GroupElement` is all zero, `scalarmult()` returns `Err(())` since
/// the resulting `GroupElement` would be all zero, no matter the `Scalar`.
pub fn scalarmult(n: &Scalar, p: &GroupElement) -> Result<GroupElement, ()> {
    let mut q = [0; GROUPELEMENTBYTES];
    unsafe {
        if ffi::crypto_scalarmult_ed25519(q.as_mut_ptr(), n.0.as_ptr(), p.0.as_ptr()) != 0 {
            Err(())
        } else {
            Ok(GroupElement(q))
        }
    }
}

/// `scalarmult_base()` computes the scalar product of a standard
/// group element and an integer `n`. It returns the resulting
/// group element `q`/
pub fn scalarmult_base(n: &Scalar) -> GroupElement {
    let mut q = [0; GROUPELEMENTBYTES];
    unsafe {
        ffi::crypto_scalarmult_ed25519_base(q.as_mut_ptr(), n.0.as_ptr());
    }
    GroupElement(q)
}

#[cfg(test)]
mod test {
    use super::*;
    use randombytes::randombytes_into;

    #[test]
    fn test_vector_1() {
        // https://tools.ietf.org/html/rfc8032#page-24
        let sk = [
            0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec,
            0x2c, 0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03,
            0x1c, 0xae, 0x7f, 0x60,
        ];
        let pk_expected = [
            0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64,
            0x07, 0x3a, 0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68,
            0xf7, 0x07, 0x51, 0x1a,
        ];

        // derive key using algorithm descriped in rfc8032 section 5.1.5
        // https://tools.ietf.org/html/rfc8032#page-13
        use crate::crypto::hash::sha512::{hash, Digest};
        let Digest(mut h) = hash(&sk);
        h[0] &= 0xF8;
        h[31] |= 0x40;

        let mut n = [0u8; SCALARBYTES];
        n.copy_from_slice(&h[0..SCALARBYTES]);
        let GroupElement(pk) = scalarmult_base(&Scalar(n));
        assert!(pk == pk_expected);

        // do the same thing but using the base (B) constant for ed25519
        let b = [
            0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
            0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
            0x66, 0x66, 0x66, 0x66,
        ];

        let GroupElement(pk) = scalarmult(&Scalar(n), &GroupElement(b)).unwrap();
        assert!(pk == pk_expected);
    }

    #[test]
    #[should_panic]
    fn test_all_zero() {
        let mut sk = [0; SCALARBYTES];
        randombytes_into(&mut sk);
        let sk = Scalar(sk);
        let pk = GroupElement([0; GROUPELEMENTBYTES]);
        let _ = scalarmult(&sk, &pk).unwrap();
    }
}

#[cfg(feature = "benchmarks")]
#[cfg(test)]
mod bench {
    extern crate test;
    use super::*;
    use randombytes::randombytes_into;

    #[bench]
    fn bench_scalarmult(b: &mut test::Bencher) {
        let mut g = GroupElement([0u8; GROUPELEMENTBYTES]);
        let mut s = Scalar([0u8; SCALARBYTES]);
        randombytes_into(&mut g.0);
        randombytes_into(&mut s.0);
        b.iter(|| {
            scalarmult(&s, &g);
        });
    }

    #[bench]
    fn bench_scalarmult_base(b: &mut test::Bencher) {
        let mut s = Scalar([0u8; SCALARBYTES]);
        randombytes_into(&mut s.0);
        b.iter(|| {
            scalarmult_base(&s);
        });
    }
}
