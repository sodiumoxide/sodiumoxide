/*!
`HMAC-SHA-512-256`, i.e., the first 256 bits of
`HMAC-SHA-512`.  `HMAC-SHA-512-256` is conjectured to meet the standard notion
of unforgeability.
*/
use std::libc::{c_ulonglong, c_int};
use randombytes::randombytes_into;
use crypto::verify::verify_32;

#[link(name = "sodium")]
#[link_args = "-lsodium"]
extern {
    fn crypto_auth_hmacsha512256(a: *mut u8,
                                 m: *u8,
                                 mlen: c_ulonglong,
                                 k: *u8) -> c_int;
    fn crypto_auth_hmacsha512256_verify(a: *u8,
                                        m: *u8,
                                        mlen: c_ulonglong,
                                        k: *u8) -> c_int;
}

pub static KEYBYTES: uint = 32;
pub static TAGBYTES: uint = 32;

/**
 * Authentication `Key`
 *
 * When a `Key` goes out of scope its contents
 * will be zeroed out
 */
pub struct Key([u8, ..KEYBYTES]);

impl Drop for Key {
    fn drop(&mut self) {
        let &Key(ref mut k) = self;
        for e in k.mut_iter() { *e = 0 }
    }
}

/**
  * Authentication `Tag`
  *
  * The tag implements the traits `TotalEq` and `Eq` using constant-time
  * comparison functions. See `sodiumoxide::crypto::verify::verify_32`
  */
pub struct Tag([u8, ..TAGBYTES]);
impl TotalEq for Tag {
    fn equals(&self, &Tag(other): &Tag) -> bool {
        let &Tag(ref tag) = self;
        verify_32(tag, &other)
    }
}
impl Eq for Tag {
    fn eq(&self, &Tag(other): &Tag) -> bool {
        let &Tag(ref tag) = self;
        verify_32(tag, &other)
    }
}

/**
 * `gen_key()` randomly generates a key for authentication
 *
 * THREAD SAFETY: `gen_key()` is thread-safe provided that you have
 * called `sodiumoxide::init()` once before using any other function
 * from sodiumoxide.
 */
pub fn gen_key() -> Key {
    let mut k = [0, ..KEYBYTES];
    randombytes_into(k);
    Key(k)
}

/**
 * `authenticate()` authenticates a message `m` using a secret key `k`.
 * The function returns an authenticator tag.
 */
pub fn authenticate(m: &[u8],
                    &Key(k): &Key) -> Tag {
    unsafe {
        let mut tag = [0, ..TAGBYTES];
        crypto_auth_hmacsha512256(tag.as_mut_ptr(),
                                  m.as_ptr(),
                                  m.len() as c_ulonglong,
                                  k.as_ptr());
        Tag(tag)
    }
}

/**
 * `verify()` returns `true` if `tag` is a correct authenticator of message `m`
 * under a secret key `k`. Otherwise it returns false.
 */
pub fn verify(&Tag(tag): &Tag, m: &[u8],
              &Key(k): &Key) -> bool {
    unsafe {
        crypto_auth_hmacsha512256_verify(tag.as_ptr(),
                                         m.as_ptr(),
                                         m.len() as c_ulonglong,
                                         k.as_ptr()) == 0
    }
}

#[test]
fn test_auth_verify() {
    use randombytes::randombytes;
    for i in range(0, 256) {
        let k = gen_key();
        let m = randombytes(i as uint);
        let tag = authenticate(m, &k);
        assert!(verify(&tag, m, &k));
    }
}

#[test]
fn test_auth_verify_tamper() {
    use randombytes::randombytes;
    for i in range(0, 256) {
        let k = gen_key();
        let mut m = randombytes(i as uint);
        let Tag(mut tagbuf) = authenticate(m, &k);
        for j in range(0, m.len()) {
            m[j] ^= 0x20;
            assert!(!verify(&Tag(tagbuf), m, &k));
            m[j] ^= 0x20;
        }
        for j in range(0, tagbuf.len()) {
            tagbuf[j] ^= 0x20;
            assert!(!verify(&Tag(tagbuf), m, &k));
            tagbuf[j] ^= 0x20;
        }
    }
}

#[test]
fn test_vector_1() {
    // corresponding to tests/auth.c from NaCl
    /* "Test Case 2" from RFC 4231 */
    let key = Key([74, 101, 102, 101, 0, 0, 0, 0
                  , 0, 0, 0, 0, 0, 0, 0, 0
                  , 0, 0, 0, 0, 0, 0, 0, 0
                  , 0, 0, 0, 0, 0, 0, 0, 0]);
    let c = [0x77, 0x68, 0x61, 0x74, 0x20, 0x64, 0x6f, 0x20
            ,0x79, 0x61, 0x20, 0x77, 0x61, 0x6e, 0x74, 0x20
            ,0x66, 0x6f, 0x72, 0x20, 0x6e, 0x6f, 0x74, 0x68
            ,0x69, 0x6e, 0x67, 0x3f];

    let a_expected = [0x16,0x4b,0x7a,0x7b,0xfc,0xf8,0x19,0xe2
                     ,0xe3,0x95,0xfb,0xe7,0x3b,0x56,0xe0,0xa3
                     ,0x87,0xbd,0x64,0x22,0x2e,0x83,0x1f,0xd6
                     ,0x10,0x27,0x0c,0xd7,0xea,0x25,0x05,0x54];

    let Tag(a) = authenticate(c, &key);
    assert!(a == a_expected);
}
