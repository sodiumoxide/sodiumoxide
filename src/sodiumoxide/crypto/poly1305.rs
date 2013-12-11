/*!
`crypto_onetimeauth_poly1305`, an authenticator specified
in [Cryptography in NaCl](http://nacl.cr.yp.to/valid.html), Section 9. This
authenticator is proven to meet the standard notion of unforgeability after a
single message.
*/
use std::libc::{c_ulonglong, c_int};
use std::vec::raw::{to_ptr, to_mut_ptr};
use randombytes::randombytes_into;
use crypto::verify::verify_16;

#[link(name = "sodium")]
#[link_args = "-lsodium"]
extern {
    fn crypto_onetimeauth_poly1305(a: *mut u8,
                                   m: *u8,
                                   mlen: c_ulonglong,
                                   k: *u8) -> c_int;
    fn crypto_onetimeauth_poly1305_verify(a: *u8,
                                          m: *u8,
                                          mlen: c_ulonglong,
                                          k: *u8) -> c_int;
}

/**
 * Length of `Key` (in bytes)
 */
pub static KEYBYTES: uint = 32;

/**
 * `Key` for one-time authentication
 *
 * When a `Key` goes out of scope its contents
 * will be zeroed out
 */
pub struct Key([u8, ..KEYBYTES]);
impl Drop for Key {
    fn drop(&mut self) {
        for e in self.mut_iter() {
            *e = 0
        }
    }
}

/**
 * Length of `Tag` (in bytes)
 */
pub static TAGBYTES: uint = 16;

/**
 * Authentication tag
 *
 * The tag implements the traits `TotalEq` and `Eq` using constant-time
 * comparison functions. See `sodiumoxide::crypto::verify::verify_16`
 */
pub struct Tag([u8, ..TAGBYTES]);
impl TotalEq for Tag {
    fn equals(&self, other: &Tag) -> bool {
        verify_16(&**self, &**other)
    }
}
impl Eq for Tag {
    fn eq(&self, other: &Tag) -> bool {
        verify_16(&**self, &**other)
    }
}

/**
 * `gen_key()` randomly generates a key for one-time authentication
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
 * `authenticate()` authenticates a message `m` using a secret key `k`
 * and returns an authenticator tag.
 */
#[fixed_stack_segment]
pub fn authenticate(m: &[u8], k: &Key) -> ~Tag {
    unsafe {
        let mut tag = ~Tag([0, ..TAGBYTES]);
        crypto_onetimeauth_poly1305(to_mut_ptr(**tag), 
                                    to_ptr(m), 
                                    m.len() as c_ulonglong, 
                                    to_ptr(**k));
        tag
    }
}

/**
 * `verify()` returns `true` if `tag` is a correct authenticator of
 * a message `m` under a secret key `k`. Otherwise `verify()` returns false.
 */
#[fixed_stack_segment]
pub fn verify(tag: &Tag, m: &[u8], k: &Key) -> bool {
    unsafe {
        crypto_onetimeauth_poly1305_verify(to_ptr(**tag), 
                                           to_ptr(m), 
                                           m.len() as c_ulonglong, 
                                           to_ptr(**k)) == 0
    }
}

#[test]
fn test_onetimeauth_verify() {
    use randombytes::randombytes;
    for i in range(0, 256) {
        let k = gen_key();
        let m = randombytes(i as uint);
        let tag = authenticate(m, k);
        assert!(verify(tag, m, k));
    }
}

#[test]
fn test_onetimeauth_verify_tamper() {
    use randombytes::randombytes;
    for i in range(0, 256) {
        let k = gen_key();
        let mut m = randombytes(i as uint);
        let mut tag = authenticate(m, k);
        for j in range(0, m.len()) {
            m[j] ^= 0x20;
            assert!(!verify(tag, m, k));
            assert!(tag != authenticate(m, k));
            m[j] ^= 0x20;
        }
        for j in range(0, tag.len()) {
            tag[j] ^= 0x20;
            assert!(!verify(tag, m, k));
            assert!(tag != authenticate(m, k));
            tag[j] ^= 0x20;
        }
    }
}

#[test]
fn test_vector_1() {
    // corresponding to tests/onetimeauth.c, tests/onetimeauth2.c,
    // tests/onetimeauth5.cpp and tests/onetimeauth6.cpp from NaCl
    let key = Key([0xee,0xa6,0xa7,0x25,0x1c,0x1e,0x72,0x91
                  ,0x6d,0x11,0xc2,0xcb,0x21,0x4d,0x3c,0x25
                  ,0x25,0x39,0x12,0x1d,0x8e,0x23,0x4e,0x65
                  ,0x2d,0x65,0x1f,0xa4,0xc8,0xcf,0xf8,0x80]);

    let c = [0x8e,0x99,0x3b,0x9f,0x48,0x68,0x12,0x73
            ,0xc2,0x96,0x50,0xba,0x32,0xfc,0x76,0xce
            ,0x48,0x33,0x2e,0xa7,0x16,0x4d,0x96,0xa4
            ,0x47,0x6f,0xb8,0xc5,0x31,0xa1,0x18,0x6a
            ,0xc0,0xdf,0xc1,0x7c,0x98,0xdc,0xe8,0x7b
            ,0x4d,0xa7,0xf0,0x11,0xec,0x48,0xc9,0x72
            ,0x71,0xd2,0xc2,0x0f,0x9b,0x92,0x8f,0xe2
            ,0x27,0x0d,0x6f,0xb8,0x63,0xd5,0x17,0x38
            ,0xb4,0x8e,0xee,0xe3,0x14,0xa7,0xcc,0x8a
            ,0xb9,0x32,0x16,0x45,0x48,0xe5,0x26,0xae
            ,0x90,0x22,0x43,0x68,0x51,0x7a,0xcf,0xea
            ,0xbd,0x6b,0xb3,0x73,0x2b,0xc0,0xe9,0xda
            ,0x99,0x83,0x2b,0x61,0xca,0x01,0xb6,0xde
            ,0x56,0x24,0x4a,0x9e,0x88,0xd5,0xf9,0xb3
            ,0x79,0x73,0xf6,0x22,0xa4,0x3d,0x14,0xa6
            ,0x59,0x9b,0x1f,0x65,0x4c,0xb4,0x5a,0x74
            ,0xe3,0x55,0xa5];

    let a_expected = Tag([0xf3,0xff,0xc7,0x70,0x3f,0x94,0x00,0xe5
                         ,0x2a,0x7d,0xfb,0x4b,0x3d,0x33,0x05,0xd9]);
    let a = authenticate(c, &key);
    assert!(*a == a_expected);
    assert!(verify(a, c, &key));
}
