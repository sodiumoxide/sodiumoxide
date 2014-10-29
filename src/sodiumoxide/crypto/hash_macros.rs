#![macro_escape]
macro_rules! hash_module (($hash_name:ident, $hashbytes:expr, $blockbytes:expr) => (

#[link(name = "sodium")]
extern {
    fn $hash_name(h: *mut u8,
                  m: *const u8,
                  mlen: c_ulonglong) -> c_int;
}

pub const HASHBYTES: uint = $hashbytes;
pub const BLOCKBYTES: uint = $blockbytes;

/**
 * Digest-structure
 */
pub struct Digest(pub [u8, ..HASHBYTES]);

impl Clone for Digest {
    fn clone(&self) -> Digest {
        let &Digest(d) = self;
        Digest(d)
    }
}

/**
 * `hash` hashes a message `m`. It returns a hash `h`.
 */
pub fn hash(m: &[u8]) -> Digest {
    unsafe {
        let mut h = [0, ..HASHBYTES];
        $hash_name(h.as_mut_ptr(), m.as_ptr(), m.len() as c_ulonglong);
        Digest(h)
    }
}

))
