/*!
`crypto_stream_salsa20` (Salsa20/20), a particular cipher specified in
[Cryptography in NaCl](http://nacl.cr.yp.to/valid.html), Section 7.  This
cipher is conjectured to meet the standard notion of unpredictability. 
*/
use std::libc::{c_ulonglong, c_int};
use std::vec::{from_elem};
use std::vec::raw::{to_mut_ptr, to_ptr};
use utils::marshal;
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
    let (c, _) = do marshal(m, 0, 0) |dst, src, len| {
        unsafe {
            crypto_stream_salsa20_xor(dst, src, len, to_ptr(**n), to_ptr(**k))
        }
    };
    c
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
