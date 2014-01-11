/*!
`HMAC-SHA-256` `HMAC-SHA-256` is conjectured to meet the standard notion of
unforgeability.
*/
use std::libc::{c_ulonglong, c_int};
use randombytes::randombytes_into;
use crypto::verify::verify_32;

#[link(name = "sodium")]
#[link_args = "-lsodium"]
extern {
    fn crypto_auth_hmacsha256(a: *mut u8,
                                 m: *u8,
                                 mlen: c_ulonglong,
                                 k: *u8) -> c_int;
    fn crypto_auth_hmacsha256_verify(a: *u8,
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
        crypto_auth_hmacsha256(tag.as_mut_ptr(),
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
        crypto_auth_hmacsha256_verify(tag.as_ptr(),
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
    for i in range(0, 32) {
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
    // corresponding to tests/auth2.c from NaCl
    /* "Test Case AUTH256-4 from RFC 4868 */
    let key = Key([0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08
                  ,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10
                  ,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18
                  ,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f,0x20]);
    let c = [0xcd,0xcd,0xcd,0xcd,0xcd,0xcd,0xcd,0xcd
            ,0xcd,0xcd,0xcd,0xcd,0xcd,0xcd,0xcd,0xcd
            ,0xcd,0xcd,0xcd,0xcd,0xcd,0xcd,0xcd,0xcd
            ,0xcd,0xcd,0xcd,0xcd,0xcd,0xcd,0xcd,0xcd
            ,0xcd,0xcd,0xcd,0xcd,0xcd,0xcd,0xcd,0xcd
            ,0xcd,0xcd,0xcd,0xcd,0xcd,0xcd,0xcd,0xcd
            ,0xcd,0xcd];
    let a_expected = Tag([0x37,0x2e,0xfc,0xf9,0xb4,0x0b,0x35,0xc2
                         ,0x11,0x5b,0x13,0x46,0x90,0x3d,0x2e,0xf4
                         ,0x2f,0xce,0xd4,0x6f,0x08,0x46,0xe7,0x25
                         ,0x7b,0xb1,0x56,0xd3,0xd7,0xb3,0x0d,0x3f]);
    let a = authenticate(c, &key);
    assert!(a == a_expected);
}
