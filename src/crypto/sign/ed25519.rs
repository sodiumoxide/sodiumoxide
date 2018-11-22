//! `ed25519`, a signature scheme specified in
//! [Ed25519](http://ed25519.cr.yp.to/). This function is conjectured to meet the
//! standard notion of unforgeability for a public-key signature scheme under
//! chosen-message attacks.

use ffi;
use libc::c_ulonglong;

/// Number of bytes in a `Seed`.
pub const SEEDBYTES: usize = ffi::crypto_sign_ed25519_SEEDBYTES as usize;

/// Number of bytes in a `SecretKey`.
pub const SECRETKEYBYTES: usize = ffi::crypto_sign_ed25519_SECRETKEYBYTES as usize;

/// Number of bytes in a `PublicKey`.
pub const PUBLICKEYBYTES: usize = ffi::crypto_sign_ed25519_PUBLICKEYBYTES as usize;

/// Number of bytes in a `Signature`.
pub const SIGNATUREBYTES: usize = ffi::crypto_sign_ed25519_BYTES as usize;

new_type! {
    /// `Seed` that can be used for keypair generation
    ///
    /// The `Seed` is used by `keypair_from_seed()` to generate
    /// a secret and public signature key.
    ///
    /// When a `Seed` goes out of scope its contents
    /// will be zeroed out
    secret Seed(SEEDBYTES);
}

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

new_type! {
    /// Detached signature
    public Signature(SIGNATUREBYTES);
}

/// `gen_keypair()` randomly generates a secret key and a corresponding public
/// key.
///
/// THREAD SAFETY: `gen_keypair()` is thread-safe provided that you have
/// called `rust_sodium::init()` once before using any other function
/// from `rust_sodium`.
pub fn gen_keypair() -> (PublicKey, SecretKey) {
    unsafe {
        let mut pk = [0u8; PUBLICKEYBYTES];
        let mut sk = [0u8; SECRETKEYBYTES];
        let _todo_use_result = ffi::crypto_sign_ed25519_keypair(pk.as_mut_ptr(), sk.as_mut_ptr());
        (PublicKey(pk), SecretKey(sk))
    }
}

/// `keypair_from_seed()` computes a secret key and a corresponding public key
/// from a `Seed`.
pub fn keypair_from_seed(&Seed(ref seed): &Seed) -> (PublicKey, SecretKey) {
    unsafe {
        let mut pk = [0u8; PUBLICKEYBYTES];
        let mut sk = [0u8; SECRETKEYBYTES];
        let _todo_use_result =
            ffi::crypto_sign_ed25519_seed_keypair(pk.as_mut_ptr(), sk.as_mut_ptr(), seed.as_ptr());
        (PublicKey(pk), SecretKey(sk))
    }
}

/// `sign()` signs a message `m` using the signer's secret key `sk`.
/// `sign()` returns the resulting signed message `sm`.
pub fn sign(m: &[u8], &SecretKey(ref sk): &SecretKey) -> Vec<u8> {
    unsafe {
        let mut sm = vec![0u8; m.len() + SIGNATUREBYTES];
        let mut smlen = 0;
        let _todo_use_result = ffi::crypto_sign_ed25519(
            sm.as_mut_ptr(),
            &mut smlen,
            m.as_ptr(),
            m.len() as c_ulonglong,
            sk.as_ptr(),
        );
        sm.truncate(smlen as usize);
        sm
    }
}

/// `verify()` verifies the signature in `sm` using the signer's public key `pk`.
/// `verify()` returns the message `Ok(m)`.
/// If the signature fails verification, `verify()` returns `Err(())`.
pub fn verify(sm: &[u8], &PublicKey(ref pk): &PublicKey) -> Result<Vec<u8>, ()> {
    unsafe {
        let mut m = vec![0u8; sm.len()];
        let mut mlen = 0;
        if ffi::crypto_sign_ed25519_open(
            m.as_mut_ptr(),
            &mut mlen,
            sm.as_ptr(),
            sm.len() as c_ulonglong,
            pk.as_ptr(),
        ) == 0
        {
            m.truncate(mlen as usize);
            Ok(m)
        } else {
            Err(())
        }
    }
}

/// `sign_detached()` signs a message `m` using the signer's secret key `sk`.
/// `sign_detached()` returns the resulting signature `sig`.
pub fn sign_detached(m: &[u8], &SecretKey(ref sk): &SecretKey) -> Signature {
    unsafe {
        let mut sig = [0u8; SIGNATUREBYTES];
        let mut siglen: c_ulonglong = 0;
        let _todo_use_result = ffi::crypto_sign_ed25519_detached(
            sig.as_mut_ptr(),
            &mut siglen,
            m.as_ptr(),
            m.len() as c_ulonglong,
            sk.as_ptr(),
        );
        assert_eq!(siglen, SIGNATUREBYTES as c_ulonglong);
        Signature(sig)
    }
}

/// `verify_detached()` verifies the signature in `sig` against the message `m`
/// and the signer's public key `pk`.
/// `verify_detached()` returns true if the signature is valid, false otherwise.
pub fn verify_detached(
    &Signature(ref sig): &Signature,
    m: &[u8],
    &PublicKey(ref pk): &PublicKey,
) -> bool {
    unsafe {
        0 == ffi::crypto_sign_ed25519_verify_detached(
            sig.as_ptr(),
            m.as_ptr(),
            m.len() as c_ulonglong,
            pk.as_ptr(),
        )
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_sign_verify() {
        use randombytes::randombytes;
        unwrap!(::init());
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
        unwrap!(::init());
        for i in 0..32usize {
            let (pk, sk) = gen_keypair();
            let m = randombytes(i);
            let mut sm = sign(&m, &sk);
            for j in 0..sm.len() {
                sm[j] ^= 0x20;
                assert!(Err(()) == verify(&sm, &pk));
                sm[j] ^= 0x20;
            }
        }
    }

    #[test]
    fn test_sign_verify_detached() {
        use randombytes::randombytes;
        unwrap!(::init());
        for i in 0..256usize {
            let (pk, sk) = gen_keypair();
            let m = randombytes(i);
            let sig = sign_detached(&m, &sk);
            assert!(verify_detached(&sig, &m, &pk));
        }
    }

    #[test]
    fn test_sign_verify_detached_tamper() {
        use randombytes::randombytes;
        unwrap!(::init());
        for i in 0..32usize {
            let (pk, sk) = gen_keypair();
            let m = randombytes(i);
            let Signature(mut sig) = sign_detached(&m, &sk);
            for j in 0..SIGNATUREBYTES {
                sig[j] ^= 0x20;
                assert!(!verify_detached(&Signature(sig), &m, &pk));
                sig[j] ^= 0x20;
            }
        }
    }

    #[test]
    fn test_sign_verify_seed() {
        use randombytes::{randombytes, randombytes_into};
        unwrap!(::init());
        for i in 0..256usize {
            let mut seedbuf = [0; 32];
            randombytes_into(&mut seedbuf);
            let seed = Seed(seedbuf);
            let (pk, sk) = keypair_from_seed(&seed);
            let m = randombytes(i);
            let sm = sign(&m, &sk);
            let m2 = verify(&sm, &pk);
            assert!(Ok(m) == m2);
        }
    }

    #[test]
    fn test_sign_verify_tamper_seed() {
        use randombytes::{randombytes, randombytes_into};
        unwrap!(::init());
        for i in 0..32usize {
            let mut seedbuf = [0; 32];
            randombytes_into(&mut seedbuf);
            let seed = Seed(seedbuf);
            let (pk, sk) = keypair_from_seed(&seed);
            let m = randombytes(i);
            let mut sm = sign(&m, &sk);
            for j in 0..sm.len() {
                sm[j] ^= 0x20;
                assert!(Err(()) == verify(&sm, &pk));
                sm[j] ^= 0x20;
            }
        }
    }

    #[test]
    fn test_vectors() {
        // test vectors from the Python implementation
        // from the [Ed25519 Homepage](http://ed25519.cr.yp.to/software.html)
        use hex;
        use std::fs::File;
        use std::io::{BufRead, BufReader};

        unwrap!(::init());
        let r = BufReader::new(unwrap!(File::open("testvectors/ed25519.input")));
        for mline in r.lines() {
            let line = unwrap!(mline);
            let mut x = line.split(':');
            let x0 = unwrap!(x.next());
            let x1 = unwrap!(x.next());
            let x2 = unwrap!(x.next());
            let x3 = unwrap!(x.next());
            let seed_bytes = unwrap!(hex::decode(&x0[..64]));
            assert!(seed_bytes.len() == SEEDBYTES);
            let mut seedbuf = [0u8; SEEDBYTES];
            for (s, b) in seedbuf.iter_mut().zip(seed_bytes.iter()) {
                *s = *b
            }
            let seed = Seed(seedbuf);
            let (pk, sk) = keypair_from_seed(&seed);
            let m = unwrap!(hex::decode(x2));
            let sm = sign(&m, &sk);
            assert!(unwrap!(verify(&sm, &pk)) == m);
            assert!(x1 == hex::encode(&pk[..]));
            assert!(x3 == hex::encode(&sm));
        }
    }

    #[test]
    fn test_vectors_detached() {
        // test vectors from the Python implementation
        // from the [Ed25519 Homepage](http://ed25519.cr.yp.to/software.html)
        use hex;
        use std::fs::File;
        use std::io::{BufRead, BufReader};

        unwrap!(::init());
        let r = BufReader::new(unwrap!(File::open("testvectors/ed25519.input")));
        for mline in r.lines() {
            let line = unwrap!(mline);
            let mut x = line.split(':');
            let x0 = unwrap!(x.next());
            let x1 = unwrap!(x.next());
            let x2 = unwrap!(x.next());
            let x3 = unwrap!(x.next());
            let seed_bytes = unwrap!(hex::decode(&x0[..64]));
            assert!(seed_bytes.len() == SEEDBYTES);
            let mut seedbuf = [0u8; SEEDBYTES];
            for (s, b) in seedbuf.iter_mut().zip(seed_bytes.iter()) {
                *s = *b
            }
            let seed = Seed(seedbuf);
            let (pk, sk) = keypair_from_seed(&seed);
            let m = unwrap!(hex::decode(&x2));
            let sig = sign_detached(&m, &sk);
            assert!(verify_detached(&sig, &m, &pk));
            assert!(x1 == hex::encode(&pk[..]));
            let sm = hex::encode(&sig[..]) + x2; // x2 is m hex encoded
            assert!(x3 == sm);
        }
    }

    #[test]
    fn test_serialisation() {
        use randombytes::randombytes;
        use test_utils::round_trip;
        unwrap!(::init());
        for i in 0..256usize {
            let (pk, sk) = gen_keypair();
            let m = randombytes(i);
            let sig = sign_detached(&m, &sk);
            round_trip(&pk);
            round_trip(&sk);
            round_trip(&sig);
        }
    }
}

#[cfg(feature = "benchmarks")]
#[cfg(test)]
mod bench {
    extern crate test;
    use super::*;
    use randombytes::randombytes;

    const BENCH_SIZES: [usize; 14] = [0, 1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096];

    #[bench]
    fn bench_sign(b: &mut test::Bencher) {
        unwrap!(::init());
        let (_, sk) = gen_keypair();
        let ms: Vec<Vec<u8>> = BENCH_SIZES.iter().map(|s| randombytes(*s)).collect();
        b.iter(|| {
            for m in ms.iter() {
                sign(m, &sk);
            }
        });
    }

    #[bench]
    fn bench_verify(b: &mut test::Bencher) {
        unwrap!(::init());
        let (pk, sk) = gen_keypair();
        let sms: Vec<Vec<u8>> = BENCH_SIZES
            .iter()
            .map(|s| {
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
