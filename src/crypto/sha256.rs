/*!
`SHA-256`.

There has been considerable degradation of public confidence in the
security conjectures for many hash functions, including `SHA-256`.
However, for the moment, there do not appear to be alternatives that
inspire satisfactory levels of confidence. One can hope that NIST's
SHA-3 competition will improve the situation.
*/
use std::libc::{c_ulonglong, c_int};
use std::vec::raw::{to_mut_ptr, to_ptr};

#[link(name = "sodium")]
#[link_args = "-lsodium"]
extern {
    fn crypto_hash_sha256(h: *mut u8,
                          m: *u8,
                          mlen: c_ulonglong) -> c_int;
}

pub static HASHBYTES: uint = 32;
pub static BLOCKBYTES: uint = 64;

/**
 * Digest-structure
 */
pub struct Digest([u8, ..HASHBYTES]);

/**
 * `hash` hashes a message `m`. It returns a hash `h`.
 */
#[fixed_stack_segment]
pub fn hash(m: &[u8]) -> ~Digest {
    unsafe {
        let mut h = ~Digest([0, ..HASHBYTES]);
        crypto_hash_sha256(to_mut_ptr(**h), to_ptr(m), m.len() as c_ulonglong);
        h
    }
}
