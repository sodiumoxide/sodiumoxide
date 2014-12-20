/*!
WARNING: This signature software is a prototype. It has been replaced by the final system
[Ed25519](http://ed25519.cr.yp.to/). It is only kept here for compatibility reasons.
*/
use ffi;
use libc::c_ulonglong;
use std::intrinsics::volatile_set_memory;

pub const SECRETKEYBYTES: uint = ffi::crypto_sign_edwards25519sha512batch_SECRETKEYBYTES as uint;
pub const PUBLICKEYBYTES: uint = ffi::crypto_sign_edwards25519sha512batch_PUBLICKEYBYTES as uint;
pub const SIGNATUREBYTES: uint = ffi::crypto_sign_edwards25519sha512batch_BYTES as uint;

/**
 * `SecretKey` for signatures
 *
 * When a `SecretKey` goes out of scope its contents
 * will be zeroed out
 */
pub struct SecretKey(pub [u8, ..SECRETKEYBYTES]);

newtype_drop!(SecretKey);
newtype_clone!(SecretKey);
newtype_impl!(SecretKey, SECRETKEYBYTES);

/**
 * `PublicKey` for signatures
 */
#[deriving(Copy)]
pub struct PublicKey(pub [u8, ..PUBLICKEYBYTES]);

newtype_clone!(PublicKey);
newtype_impl!(PublicKey, PUBLICKEYBYTES);

/**
 * `gen_keypair()` randomly generates a secret key and a corresponding public
 * key.
 *
 * THREAD SAFETY: `gen_keypair()` is thread-safe provided that you have
 * called `sodiumoxide::init()` once before using any other function
 * from sodiumoxide.
 */
pub fn gen_keypair() -> (PublicKey, SecretKey) {
    unsafe {
        let mut pk = [0u8, ..PUBLICKEYBYTES];
        let mut sk = [0u8, ..SECRETKEYBYTES];
        ffi::crypto_sign_edwards25519sha512batch_keypair(pk.as_mut_ptr(),
                                                    sk.as_mut_ptr());
        (PublicKey(pk), SecretKey(sk))
    }
}

/**
 * `sign()` signs a message `m` using the signer's secret key `sk`.
 * `sign()` returns the resulting signed message `sm`.
 */
pub fn sign(m: &[u8],
            &SecretKey(sk): &SecretKey) -> Vec<u8> {
    unsafe {
        let mut sm = Vec::from_elem(m.len() + SIGNATUREBYTES, 0u8);
        let mut smlen = 0;
        ffi::crypto_sign_edwards25519sha512batch(sm.as_mut_ptr(),
                                            &mut smlen,
                                            m.as_ptr(),
                                            m.len() as c_ulonglong,
                                            sk.as_ptr());
        sm.truncate(smlen as uint);
        sm
    }
}

/**
 * `verify()` verifies the signature in `sm` using the signer's public key `pk`.
 * `verify()` returns the message `Some(m)`.
 * If the signature fails verification, `verify()` returns `None`.
 */
pub fn verify(sm: &[u8],
              &PublicKey(pk): &PublicKey) -> Option<Vec<u8>> {
    unsafe {
        let mut m = Vec::from_elem(sm.len(), 0u8);
        let mut mlen = 0;
        if ffi::crypto_sign_edwards25519sha512batch_open(m.as_mut_ptr(),
                                                    &mut mlen,
                                                    sm.as_ptr(),
                                                    sm.len() as c_ulonglong,
                                                    pk.as_ptr()) == 0 {
            m.truncate(mlen as uint);
            Some(m)
        } else {
            None
        }
    }
}

#[test]
fn test_sign_verify() {
    use randombytes::randombytes;
    for i in range(0, 256u) {
        let (pk, sk) = gen_keypair();
        let m = randombytes(i);
        let sm = sign(m.as_slice(), &sk);
        let m2 = verify(sm.as_slice(), &pk);
        assert!(Some(m) == m2);
    }
}

#[test]
fn test_sign_verify_tamper() {
    use randombytes::randombytes;
    for i in range(0, 32u) {
        let (pk, sk) = gen_keypair();
        let m = randombytes(i);
        let mut smv = sign(m.as_slice(), &sk);
        let sm = smv.as_mut_slice();
        for j in range(0, sm.len()) {
            sm[j] ^= 0x20;
            assert!(None == verify(sm, &pk));
            sm[j] ^= 0x20;
        }
    }
}

#[cfg(test)]
mod bench {
    extern crate test;
    use randombytes::randombytes;
    use super::*;

    const BENCH_SIZES: [uint, ..14] = [0, 1, 2, 4, 8, 16, 32, 64,
                                       128, 256, 512, 1024, 2048, 4096];

    #[bench]
    fn bench_sign(b: &mut test::Bencher) {
        let (_, sk) = gen_keypair();
        let ms: Vec<Vec<u8>> = BENCH_SIZES.iter().map(|s| {
            randombytes(*s)
        }).collect();
        b.iter(|| {
            for m in ms.iter() {
                sign(m.as_slice(), &sk);
            }
        });
    }

    #[bench]
    fn bench_verify(b: &mut test::Bencher) {
        let (pk, sk) = gen_keypair();
        let sms: Vec<Vec<u8>> = BENCH_SIZES.iter().map(|s| {
            let m = randombytes(*s);
            sign(m.as_slice(), &sk)
        }).collect();
        b.iter(|| {
            for sm in sms.iter() {
                verify(sm.as_slice(), &pk);
            }
        });
    }
}
