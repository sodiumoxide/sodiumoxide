/*!
`crypto_stream_salsa20` (Salsa20/20), a particular cipher specified in
[Cryptography in NaCl](http://nacl.cr.yp.to/valid.html), Section 7.  This
cipher is conjectured to meet the standard notion of unpredictability. 
*/
use std::libc::{c_ulonglong, c_int};
use std::vec::{from_elem};
use std::vec::raw::{to_mut_ptr, to_ptr};
use randombytes::randombytes_into;

#[link(name = "sodium")]
#[link_args = "-lsodium"]
extern {
    fn crypto_stream_salsa20(c: *mut u8,
                             clen: c_ulonglong,
                             n: *u8,
                             k: *u8) -> c_int;
    fn crypto_stream_salsa20_xor(c: *mut u8,
                                 m: *u8,
                                 mlen: c_ulonglong,
                                 n: *u8,
                                 k: *u8) -> c_int;
}

pub static KEYBYTES: uint = 32;
pub static NONCEBYTES: uint = 8;

/**
 * `Key` for symmetric encryption
 * 
 * When a `Key` goes out of scope its contents
 * will be zeroed out
 */
pub struct Key([u8, ..KEYBYTES]);
impl Drop for Key {
    fn drop(&mut self) { 
        for e in self.mut_iter() { *e = 0 }
    }
}

/**
 * `Nonce` for symmetric encryption
 */
pub struct Nonce([u8, ..NONCEBYTES]);

/**
 * `gen_key()` randomly generates a key for symmetric encryption
 *
 * THREAD SAFETY: `gen_key()` is thread-safe provided that you have
 * called `sodiumoxide::init()` once before using any other function
 * from sodiumoxide.
 */
pub fn gen_key() -> ~Key {
    let mut key = ~Key([0, ..KEYBYTES]);
    randombytes_into(**key);
    key
}

/**
 * `gen_nonce()` randomly generates a nonce for symmetric encryption
 *
 * THREAD SAFETY: `gen_nonce()` is thread-safe provided that you have
 * called `sodiumoxide::init()` once before using any other function
 * from sodiumoxide.
 *
 * NOTE: `gen_nonce()` isn't public because random 8-byte nonces
 * have a large probability of collisions
 */
fn gen_nonce() -> ~Nonce {
    let mut nonce = ~Nonce([0, ..NONCEBYTES]);
    randombytes_into(**nonce);
    nonce
}

/**
 * `stream()` produces a `len`-byte stream `c` as a function of a
 * secret key `k` and a nonce `n`.
 */
#[fixed_stack_segment]
pub fn stream(len: uint, n: &Nonce, k: &Key) -> ~[u8] {
    unsafe {
        let mut c = from_elem(len, 0u8);
        crypto_stream_salsa20(to_mut_ptr(c), 
                              c.len() as c_ulonglong, 
                              to_ptr(**n), 
                              to_ptr(**k));
        c
    }
}

/**
 * `stream_xor()` encrypts a message `m` using a secret key `k` and a nonce `n`.
 * The `stream_xor()` function returns the ciphertext `c`.
 *
 * `stream_xor()` guarantees that the ciphertext has the same length as the plaintext,
 * and is the plaintext xor the output of `stream()`.
 * Consequently `stream_xor()` can also be used to decrypt.
 */
#[fixed_stack_segment]
pub fn stream_xor(m: &[u8], n: &Nonce, k: &Key) -> ~[u8] {
    unsafe {
        let mut c = from_elem(m.len(), 0u8);
        crypto_stream_salsa20_xor(to_mut_ptr(c),
                                  to_ptr(m),
                                  m.len() as c_ulonglong,
                                  to_ptr(**n),
                                  to_ptr(**k));
        c
    }
}

/**
* `stream_xor_inplace` encrypts a message `m` using a secret key `k` and a nonce `n`.
* The `stream_xor_inplace()` function encrypts the message in place.
*
* `stream_xor_inplace()` guarantees that the ciphertext has the same length as
* the plaintext, and is the plaintext xor the output of `stream_inplace()`.
* Consequently `stream_xor_inplace()` can also be used to decrypt.
*/
#[fixed_stack_segment]
pub fn stream_xor_inplace(m: &mut [u8], n: &Nonce, k: &Key) {
    unsafe {
        crypto_stream_salsa20_xor(to_mut_ptr(m), 
                                  to_ptr(m), 
                                  m.len() as c_ulonglong, 
                                  to_ptr(**n), 
                                  to_ptr(**k));
    }
}

#[test]
fn test_encrypt_decrypt() {
    use randombytes::randombytes;
    for i in range(0, 1024) {
        let k = gen_key();
        let n = gen_nonce();
        let m = randombytes(i as uint);
        let c = stream_xor(m, n, k);
        let m2 = stream_xor(c, n, k);
        assert!(m == m2);
    }
}

#[test]
fn test_stream_xor() {
    use randombytes::randombytes;
    for i in range(0, 1024) {
        let k = gen_key();
        let n = gen_nonce();
        let m = randombytes(i as uint);
        let mut c = m.clone();
        let s = stream(c.len(), n, k);
        for (e, v) in c.mut_iter().zip(s.iter()) {
            *e ^= *v;
        }
        let c2 = stream_xor(m, n, k);
        assert!(c == c2);
    }
}

#[test]
fn test_stream_xor_inplace() {
    use randombytes::randombytes;
    for i in range(0, 1024) {
        let k = gen_key();
        let n = gen_nonce();
        let mut m = randombytes(i as uint);
        let mut c = m.clone();
        let s = stream(c.len(), n, k);
        for (e, v) in c.mut_iter().zip(s.iter()) {
            *e ^= *v;
        }
        stream_xor_inplace(m, n, k);
        assert!(c == m);
    }
}

#[test]
fn test_vector_1() {
    // corresponding to tests/stream2.c and tests/stream6.cpp from NaCl
    use crypto::hash::sha256::{hash, Digest};
    let secondkey = Key([0xdc,0x90,0x8d,0xda,0x0b,0x93,0x44,0xa9
                        ,0x53,0x62,0x9b,0x73,0x38,0x20,0x77,0x88
                        ,0x80,0xf3,0xce,0xb4,0x21,0xbb,0x61,0xb9
                        ,0x1c,0xbd,0x4c,0x3e,0x66,0x25,0x6c,0xe4]);
    let noncesuffix = Nonce([0x82,0x19,0xe0,0x03,0x6b,0x7a,0x0b,0x37]);
    let output = stream(4194304, &noncesuffix, &secondkey);
    let digest_expected = Digest([0x66, 0x2b, 0x9d, 0x0e, 0x34, 0x63, 0x02, 0x91, 
                                  0x56, 0x06, 0x9b, 0x12, 0xf9, 0x18, 0x69, 0x1a, 
                                  0x98, 0xf7, 0xdf, 0xb2, 0xca, 0x03, 0x93, 0xc9, 
                                  0x6b, 0xbf, 0xc6, 0xb1, 0xfb, 0xd6, 0x30, 0xa2]);
    let digest = hash(output);
    assert!(**digest == *digest_expected);
}
