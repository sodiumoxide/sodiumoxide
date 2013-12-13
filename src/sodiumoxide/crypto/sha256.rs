/*!
`SHA-256`.

There has been considerable degradation of public confidence in the
security conjectures for many hash functions, including `SHA-256`.
However, for the moment, there do not appear to be alternatives that
inspire satisfactory levels of confidence. One can hope that NIST's
SHA-3 competition will improve the situation.
*/
extern mod extra;
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
pub fn hash(m: &[u8]) -> Digest {
    unsafe {
        let mut h = Digest([0, ..HASHBYTES]);
        crypto_hash_sha256(to_mut_ptr(*h), to_ptr(m), m.len() as c_ulonglong);
        h
    }
}

#[test]
fn test_vector_1() {
    // hash of empty string
    let x = [];
    let h_expected = Digest([0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 
                             0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24, 
                             0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 
                             0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55]);
    let h = hash(x);
    assert!((*h) == (*h_expected));
}

#[test]
fn test_vector_2() {
    // The quick brown fox jumps over the lazy dog
    let x = [0x54, 0x68, 0x65, 0x20, 0x71, 0x75, 0x69, 0x63, 
             0x6b, 0x20, 0x62, 0x72, 0x6f, 0x77, 0x6e, 0x20, 
             0x66, 0x6f, 0x78, 0x20, 0x6a, 0x75, 0x6d, 0x70, 
             0x73, 0x20, 0x6f, 0x76, 0x65, 0x72, 0x20, 0x74, 
             0x68, 0x65, 0x20, 0x6c, 0x61, 0x7a, 0x79, 0x20, 
             0x64, 0x6f, 0x67];
    let h_expected = Digest([0xd7, 0xa8, 0xfb, 0xb3, 0x07, 0xd7, 0x80, 0x94, 
                             0x69, 0xca, 0x9a, 0xbc, 0xb0, 0x08, 0x2e, 0x4f, 
                             0x8d, 0x56, 0x51, 0xe4, 0x6d, 0x3c, 0xdb, 0x76, 
                             0x2d, 0x02, 0xd0, 0xbf, 0x37, 0xc9, 0xe5, 0x92]);
    let h = hash(x);
    assert!((*h) == (*h_expected));
}

fn test_nist_vector(filename: &str) {
    use self::extra::hex::{FromHex};
    use std::io::file_reader;

    let p = &Path(filename);
    let r = file_reader(p).unwrap();
    loop {
        let line = r.read_line();
        if r.eof() {
            break;
        }
        if line.starts_with("Len = ") {
            let s = line.slice_from(6);
            let len = from_str::<uint>(s).unwrap();
            let line2 = r.read_line();
            let rawmsg = line2.slice_from(6).from_hex().unwrap();
            let msg = rawmsg.slice_to(len/8);
            let line3 = r.read_line();
            let md = line3.slice_from(5).from_hex().unwrap();
            assert!(*hash(msg) == md);
        }
    }
}

#[test]
fn test_vectors_nist_short() {
    test_nist_vector("testvectors/SHA256ShortMsg.rsp");
}

#[test]
fn test_vectors_nist_long() {
    test_nist_vector("testvectors/SHA256LongMsg.rsp");
}
