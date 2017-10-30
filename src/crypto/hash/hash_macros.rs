macro_rules! hash_module (($hash_name:ident,
                           $hash_state:ident,
                           $hash_init:ident,
                           $hash_update:ident,
                           $hash_final:ident,
                           $hashbytes:expr,
                           $blockbytes:expr) => (

use std::mem;
use libc::c_ulonglong;

/// Number of bytes in a `Digest`.
pub const DIGESTBYTES: usize = $hashbytes;

/// Block size of the hash function.
pub const BLOCKBYTES: usize = $blockbytes;

new_type! {
    /// Digest-structure
    public Digest(DIGESTBYTES);
}

/// `hash` hashes a message `m`. It returns a hash `h`.
pub fn hash(m: &[u8]) -> Digest {
    unsafe {
        let mut h = [0; DIGESTBYTES];
        $hash_name(&mut h, m.as_ptr(), m.len() as c_ulonglong);
        Digest(h)
    }
}

/// State for multi-part (streaming) hash computation (Init-Update-Final). This method process a
/// message as a sequence of multiple chunks.
pub struct State($hash_state);

impl State {
    /// Constructs and initializes a new `State`.
    pub fn new() -> Self {
        unsafe {
            let mut st: $hash_state = mem::uninitialized();
            $hash_init(&mut st);
            State(st)
        }
    }

    /// Updates the hash with `data`. `update` can be called more than once in order to compute the
    /// hash from sequential chunks of the message. It must not be called after `finish` has been
    /// called.
    pub fn update(&mut self, data: &[u8]) {
        unsafe {
            $hash_update(&mut self.0, data.as_ptr(), data.len() as c_ulonglong);
        }
    }

    /// Finalizes the hash and returns the digest value. `finish` consumes the `State` so it
    /// cannot be used after `finish` has been called.
    pub fn finalize(mut self) -> Digest {
        unsafe {
            let mut digest = [0u8; DIGESTBYTES];
            $hash_final(&mut self.0, &mut digest);
            Digest(digest)
        }
    }
}

#[cfg(test)]
mod test_m {
    use super::*;

    #[test]
    fn test_hash_multipart() {
        use randombytes::randombytes;
        for i in 0..256usize {
            let m = randombytes(i);
            let h = hash(&m);
            let mut state = State::new();
            for b in m.chunks(3) {
                state.update(b);
            }
            let h2 = state.finalize();
            assert_eq!(h, h2);
        }
    }
}

#[cfg(feature = "serde")]
#[cfg(test)]
mod test_encode {
    use super::*;
    use test_utils::round_trip;

    #[test]
    fn test_serialisation() {
        use randombytes::randombytes;
        for i in 0..32usize {
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
