macro_rules! hash_module (($hash_name:ident, $hashbytes:expr, $blockbytes:expr) => (

use libc::c_ulonglong;
use rustc_serialize;

pub const HASHBYTES: usize = $hashbytes;
pub const BLOCKBYTES: usize = $blockbytes;

/// Digest-structure
#[derive(Copy)]
pub struct Digest(pub [u8; HASHBYTES]);

newtype_clone!(Digest);
newtype_impl!(Digest, HASHBYTES);
non_secret_newtype_impl!(Digest);

/// `hash` hashes a message `m`. It returns a hash `h`.
pub fn hash(m: &[u8]) -> Digest {
    unsafe {
        let mut h = [0; HASHBYTES];
        $hash_name(&mut h, m.as_ptr(), m.len() as c_ulonglong);
        Digest(h)
    }
}

#[cfg(test)]
mod test_encode {
    use super::*;
    use test_utils::round_trip;

    #[test]
    fn test_serialisation() {
        use randombytes::randombytes;
        for i in (0..32usize) {
            let m = randombytes(i);
            let d = hash(&m[..]);
            round_trip(d);
        }
    }
}

#[cfg(feature = "benchmarks")]
#[cfg(test)]
mod bench_m {
    extern crate test;
    use randombytes::randombytes;
    use super::*;

    const BENCH_SIZES: [usize; 14] = [0, 1, 2, 4, 8, 16, 32, 64,
                                      128, 256, 512, 1024, 2048, 4096];

    #[bench]
    fn bench_hash(b: &mut test::Bencher) {
        let ms: Vec<Vec<u8>> = BENCH_SIZES.iter().map(|s| {
            randombytes(*s)
        }).collect();
        b.iter(|| {
            for m in ms.iter() {
                hash(&m);
            }
        });
    }
}

));
