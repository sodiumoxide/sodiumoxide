/*!
`SHA-512`.

There has been considerable degradation of public confidence in the
security conjectures for many hash functions, including `SHA-512`.
However, for the moment, there do not appear to be alternatives that
inspire satisfactory levels of confidence. One can hope that NIST's
SHA-3 competition will improve the situation.
*/
#[cfg(test)]
extern crate serialize;
use libc::{c_ulonglong, c_int};

hash_module!(crypto_hash_sha512, 64, 128)

#[test]
fn test_vector_1() {
    // corresponding to tests/hash.c, tests/hash2.cpp,
    // tests/hash3.c and tests/hash4.cpp from NaCl
    let x = [0x74, 0x65, 0x73, 0x74, 0x69, 0x6e, 0x67, 0xa];
    let h_expected = [0x24, 0xf9, 0x50, 0xaa, 0xc7, 0xb9, 0xea, 0x9b
                     ,0x3c, 0xb7, 0x28, 0x22, 0x8a, 0x0c, 0x82, 0xb6
                     ,0x7c, 0x39, 0xe9, 0x6b, 0x4b, 0x34, 0x47, 0x98
                     ,0x87, 0x0d, 0x5d, 0xae, 0xe9, 0x3e, 0x3a, 0xe5
                     ,0x93, 0x1b, 0xaa, 0xe8, 0xc7, 0xca, 0xcf, 0xea
                     ,0x4b, 0x62, 0x94, 0x52, 0xc3, 0x80, 0x26, 0xa8
                     ,0x1d, 0x13, 0x8b, 0xc7, 0xaa, 0xd1, 0xaf, 0x3e
                     ,0xf7, 0xbf, 0xd5, 0xec, 0x64, 0x6d, 0x6c, 0x28];
    let Digest(h) = hash(&x);
    assert!(h.as_slice() == h_expected.as_slice());
}

#[cfg(test)]
fn test_nist_vector(filename: &str) {
    use self::serialize::hex::{FromHex};
    use std::path::Path;
    use std::io::BufferedReader;
    use std::io::File;

    let p = &Path::new(filename);
    let mut r = BufferedReader::new(File::open(p).unwrap());
    loop {
        let line = match r.read_line() {
            Err(_) => break,
            Ok(line) => line
        };
        if line.as_slice().starts_with("Len = ") {
            let s = line.as_slice().slice_from(6);
            let len:uint = from_str(s.trim()).unwrap();
            let line2 = r.read_line().unwrap();
            let rawmsg = line2.as_slice().slice_from(6).from_hex().unwrap();
            let msg = rawmsg.slice_to(len/8);
            let line3 = r.read_line().unwrap();
            let md = line3.as_slice().slice_from(5).from_hex().unwrap();
            let Digest(digest) = hash(msg);
            assert!(digest.as_slice() == md.as_slice());
        }
    }
}

#[test]
fn test_vectors_nist_short() {
    test_nist_vector("testvectors/SHA512ShortMsg.rsp");
}

#[test]
fn test_vectors_nist_long() {
    test_nist_vector("testvectors/SHA512LongMsg.rsp");
}
