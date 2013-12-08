/*!
`ed25519`, a signature scheme specified in
[Ed25519](http://ed25519.cr.yp.to/). This function is conjectured to meet the
standard notion of unforgeability for a public-key signature scheme under
chosen-message attacks.
*/
use std::libc::{c_ulonglong, c_int};
use std::vec::{from_elem};
use std::vec::raw::{to_mut_ptr, to_ptr};

#[link(name = "sodium")]
#[link_args = "-lsodium"]
extern {
    fn crypto_sign_keypair(pk: *mut u8,
                           sk: *mut u8) -> c_int;
    fn crypto_sign(sm: *mut u8,
                   smlen: *mut c_ulonglong,
                   m: *u8,
                   mlen: c_ulonglong,
                   sk: *u8) -> c_int;
    fn crypto_sign_open(m: *mut u8,
                        mlen: *mut c_ulonglong,
                        sm: *u8,
                        smlen: c_ulonglong,
                        pk: *u8) -> c_int;
}

pub static SECRETKEYBYTES: uint = 64;
pub static PUBLICKEYBYTES: uint = 32;
pub static SIGNATUREBYTES: uint = 64;

/**
 * `SecretKey` for signatures
 * 
 * When a `SecretKey` goes out of scope its contents
 * will be zeroed out
 */
pub struct SecretKey([u8, ..SECRETKEYBYTES]);
impl Drop for SecretKey {
    fn drop(&mut self) {
        for e in self.mut_iter() { *e = 0 }
    }
}
/**
 * `PublicKey` for signatures
 */
pub struct PublicKey([u8, ..PUBLICKEYBYTES]);

/**
 * `gen_keypair()` randomly generates a secret key and a corresponding public
 * key.
 *
 * THREAD SAFETY: `gen_keypair()` is thread-safe provided that you have
 * called `sodiumoxide::init()` once before using any other function
 * from sodiumoxide.
 */
#[fixed_stack_segment]
pub fn gen_keypair() -> (~PublicKey, ~SecretKey) {
    unsafe {
        let mut pk = ~PublicKey([0u8, ..PUBLICKEYBYTES]);
        let mut sk = ~SecretKey([0u8, ..SECRETKEYBYTES]);
        crypto_sign_keypair(to_mut_ptr(**pk), to_mut_ptr(**sk));
        (pk, sk)
    }
}

/**
 * `sign()` signs a message `m` using the signer's secret key `sk`.
 * `sign()` returns the resulting signed message `sm`.
 */
#[fixed_stack_segment]
pub fn sign(m: &[u8], sk: &SecretKey) -> ~[u8] {
    unsafe {
        let mut sm = from_elem(m.len() + SIGNATUREBYTES, 0u8);
        let mut smlen = 0;
        crypto_sign(to_mut_ptr(sm), &mut smlen, to_ptr(m), m.len() as c_ulonglong, to_ptr(**sk));
        sm.truncate(smlen as uint);
        sm
    }
}

/**
 * `verify()` verifies the signature in `sm` using the signer's public key `pk`.
 * `verify()` returns the message `Some(m)`.
 * If the signature fails verification, `verify()` returns `None`.
 */
#[fixed_stack_segment]
pub fn verify(sm: &[u8], pk: &PublicKey) -> Option<~[u8]> {
    unsafe {
        let mut m = from_elem(sm.len(), 0u8);
        let mut mlen = 0;
        if crypto_sign_open(to_mut_ptr(m), &mut mlen, to_ptr(sm), sm.len() as c_ulonglong, to_ptr(**pk)) == 0 {
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
    for _ in range(0, 256) {
        let (pk, sk) = gen_keypair();
        let m = randombytes(1024);
        let sm = sign(m, sk);
        let m2 = verify(sm, pk);
        assert!(Some(m) == m2);
    }
}

#[test]
fn test_sign_verify_tamper() {
    use randombytes::randombytes;
    for _ in range(0, 32) {
        let (pk, sk) = gen_keypair();
        let m = randombytes(1024);
        let mut sm = sign(m, sk);
        for i in range(0, sm.len()) {
            sm[i] ^= 0x20;
            assert!(None == verify(sm, pk));
            sm[i] ^= 0x20;
        }
    }
}
