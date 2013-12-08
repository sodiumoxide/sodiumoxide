/*!
`SHA-512`.

There has been considerable degradation of public confidence in the
security conjectures for many hash functions, including `SHA-512`.
However, for the moment, there do not appear to be alternatives that
inspire satisfactory levels of confidence. One can hope that NIST's
SHA-3 competition will improve the situation.
*/
use std::libc::{c_ulonglong, c_int};
use std::vec::raw::{to_mut_ptr, to_ptr};

#[link(name = "sodium")]
#[link_args = "-lsodium"]
extern {
    fn crypto_hash(h: *mut u8,
                   m: *u8,
                   mlen: c_ulonglong) -> c_int;
}

pub static HASHBYTES: uint = 64;
pub static BLOCKBYTES: uint = 128;

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
        crypto_hash(to_mut_ptr(**h), to_ptr(m), m.len() as c_ulonglong);
        h
    }
}

#[test]
fn test_vector_1() {
    let x = [0x74, 0x65, 0x73, 0x74, 0x69, 0x6e, 0x67, 0xa];
    let h_expected = ~Digest([0x24, 0xf9, 0x50, 0xaa, 0xc7, 0xb9, 0xea, 0x9b
                             ,0x3c, 0xb7, 0x28, 0x22, 0x8a, 0x0c, 0x82, 0xb6
                             ,0x7c, 0x39, 0xe9, 0x6b, 0x4b, 0x34, 0x47, 0x98
                             ,0x87, 0x0d, 0x5d, 0xae, 0xe9, 0x3e, 0x3a, 0xe5
                             ,0x93, 0x1b, 0xaa, 0xe8, 0xc7, 0xca, 0xcf, 0xea
                             ,0x4b, 0x62, 0x94, 0x52, 0xc3, 0x80, 0x26, 0xa8
                             ,0x1d, 0x13, 0x8b, 0xc7, 0xaa, 0xd1, 0xaf, 0x3e
                             ,0xf7, 0xbf, 0xd5, 0xec, 0x64, 0x6d, 0x6c, 0x28]);
    let h = hash(x);
    assert!((**h) == (**h_expected));
}
