//! WARNING: This signature software is a prototype. It has been replaced by the final system
//! [Ed25519](http://ed25519.cr.yp.to/). It is only kept here for compatibility reasons.
use ffi;
use libc::c_ulonglong;
use std::iter::repeat;
#[cfg(feature = "default")]
use rustc_serialize;

/// Number of bytes in a `SecretKey`.
pub const SECRETKEYBYTES: usize = ffi::crypto_sign_edwards25519sha512batch_SECRETKEYBYTES;

/// Number of bytes in a `PublicKey`.
pub const PUBLICKEYBYTES: usize = ffi::crypto_sign_edwards25519sha512batch_PUBLICKEYBYTES;

/// Number of bytes in a `Signature`.
pub const SIGNATUREBYTES: usize = ffi::crypto_sign_edwards25519sha512batch_BYTES;

new_type! {
    /// `SecretKey` for signatures
    ///
    /// When a `SecretKey` goes out of scope its contents
    /// will be zeroed out
    secret SecretKey(SECRETKEYBYTES);
}

new_type! {
    /// `PublicKey` for signatures
    public PublicKey(PUBLICKEYBYTES);
}

/// `gen_keypair()` randomly generates a secret key and a corresponding public
/// key.
///
/// THREAD SAFETY: `gen_keypair()` is thread-safe provided that you have
/// called `sodiumoxide::init()` once before using any other function
/// from sodiumoxide.
pub fn gen_keypair() -> (PublicKey, SecretKey) {
    unsafe {
        let mut pk = [0u8; PUBLICKEYBYTES];
        let mut sk = [0u8; SECRETKEYBYTES];
        ffi::crypto_sign_edwards25519sha512batch_keypair(&mut pk,
                                                         &mut sk);
        (PublicKey(pk), SecretKey(sk))
    }
}

/// `sign()` signs a message `m` using the signer's secret key `sk`.
/// `sign()` returns the resulting signed message `sm`.
pub fn sign(m: &[u8],
            &SecretKey(ref sk): &SecretKey) -> Vec<u8> {
    unsafe {
        let mut sm: Vec<u8> = repeat(0u8).take(m.len() + SIGNATUREBYTES).collect();
        let mut smlen = 0;
        ffi::crypto_sign_edwards25519sha512batch(sm.as_mut_ptr(),
                                                 &mut smlen,
                                                 m.as_ptr(),
                                                 m.len() as c_ulonglong,
                                                 sk);
        sm.truncate(smlen as usize);
        sm
    }
}

/// `verify()` verifies the signature in `sm` using the signer's public key `pk`.
/// `verify()` returns the message `Ok(m)`.
/// If the signature fails verification, `verify()` returns `Err(())`.
pub fn verify(sm: &[u8],
              &PublicKey(ref pk): &PublicKey) -> Result<Vec<u8>, ()> {
    unsafe {
        let mut m: Vec<u8> = repeat(0u8).take(sm.len()).collect();
        let mut mlen = 0;
        if ffi::crypto_sign_edwards25519sha512batch_open(m.as_mut_ptr(),
                                                         &mut mlen,
                                                         sm.as_ptr(),
                                                         sm.len() as c_ulonglong,
                                                         pk) == 0 {
            m.truncate(mlen as usize);
            Ok(m)
        } else {
            Err(())
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_sign_verify() {
        use randombytes::randombytes;
        for i in 0..256usize {
            let (pk, sk) = gen_keypair();
            let m = randombytes(i);
            let sm = sign(&m, &sk);
            let m2 = verify(&sm, &pk);
            assert!(Ok(m) == m2);
        }
    }

    #[test]
    fn test_sign_verify_tamper() {
        use randombytes::randombytes;
        for i in 0..32usize {
            let (pk, sk) = gen_keypair();
            let m = randombytes(i);
            let mut sm = sign(&m, &sk);
            for j in 0..sm.len() {
                sm[j] ^= 0x20;
                assert!(Err(()) == verify(&mut sm, &pk));
                sm[j] ^= 0x20;
            }
        }
    }
}

#[cfg(feature = "benchmarks")]
#[cfg(test)]
mod bench {
    extern crate test;
    use randombytes::randombytes;
    use super::*;

    const BENCH_SIZES: [usize; 14] = [0, 1, 2, 4, 8, 16, 32, 64,
                                      128, 256, 512, 1024, 2048, 4096];

    #[bench]
    fn bench_sign(b: &mut test::Bencher) {
        let (_, sk) = gen_keypair();
        let ms: Vec<Vec<u8>> = BENCH_SIZES.iter().map(|s| {
            randombytes(*s)
        }).collect();
        b.iter(|| {
            for m in ms.iter() {
                sign(m, &sk);
            }
        });
    }

    #[bench]
    fn bench_verify(b: &mut test::Bencher) {
        let (pk, sk) = gen_keypair();
        let sms: Vec<Vec<u8>> = BENCH_SIZES.iter().map(|s| {
            let m = randombytes(*s);
            sign(&m, &sk)
        }).collect();
        b.iter(|| {
            for sm in sms.iter() {
                verify(sm, &pk);
            }
        });
    }
}
