/*!
Secret-key encryption

# Security Model
The `stream()` function, viewed as a function of the nonce for a
uniform random key, is designed to meet the standard notion of
unpredictability ("PRF"). For a formal definition see, e.g., Section 2.3
of Bellare, Kilian, and Rogaway, "The security of the cipher block
chaining message authentication code," Journal of Computer and System
Sciences 61 (2000), 362–399;
http://www-cse.ucsd.edu/~mihir/papers/cbc.html.

This means that an attacker cannot distinguish this function from a
uniform random function. Consequently, if a series of messages is
encrypted by `stream_xor()` with a different nonce for each message,
the ciphertexts are indistinguishable from uniform random strings of the
same length.

Note that the length is not hidden. Note also that it is the caller's
responsibility to ensure the uniqueness of nonces—for example, by using
nonce 1 for the first message, nonce 2 for the second message, etc.
Nonces are long enough that randomly generated nonces have negligible
risk of collision.

NaCl does not make any promises regarding the resistance of `stream()` to
"related-key attacks." It is the caller's responsibility to use proper
key-derivation functions. 

# Selected primitive
`stream()` is `crypto_stream_xsalsa20`, a particular cipher specified in
[Cryptography in NaCl](http://nacl.cr.yp.to/valid.html), Section 7.
This cipher is conjectured to meet the standard notion of
unpredictability. 
*/
use std::libc::{c_ulonglong, c_int};
use std::vec::{from_elem};
use std::vec::raw::{to_mut_ptr, to_ptr};
use utils::marshal;
use randombytes::randombytes_into;

#[link(name = "sodium")]
#[link_args = "-lsodium"]
extern {
    fn crypto_stream(c: *mut u8,
                     clen: c_ulonglong,
                     n: *u8,
                     k: *u8) -> c_int;
    fn crypto_stream_xor(c: *mut u8,
                         m: *u8,
                         mlen: c_ulonglong,
                         n: *u8,
                         k: *u8) -> c_int;
}

pub static KEYBYTES: uint = 32;
pub static NONCEBYTES: uint = 24;

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
fn gen_key() -> ~Key {
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
fn stream(len: uint, n: &Nonce, k: &Key) -> ~[u8] {
    unsafe {
        let mut c = from_elem(len, 0u8);
        crypto_stream(to_mut_ptr(c), c.len() as c_ulonglong, to_ptr(**n), to_ptr(**k));
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
fn stream_xor(m: &[u8], n: &Nonce, k: &Key) -> ~[u8] {
    let (c, _) = do marshal(m, 0, 0) |dst, src, len| {
        unsafe {
            crypto_stream_xor(dst, src, len, to_ptr(**n), to_ptr(**k))
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
fn stream_xor_inplace(m: &mut [u8], n: &Nonce, k: &Key) {
    unsafe {
        crypto_stream_xor(to_mut_ptr(m), 
                          to_ptr(m), 
                          m.len() as c_ulonglong, 
                          to_ptr(**n), 
                          to_ptr(**k));
    }
}
