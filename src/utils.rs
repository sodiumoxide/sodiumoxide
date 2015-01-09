use libc::c_ulonglong;

#[doc(hidden)]
pub fn marshal<T, F>(buf: &[u8],
                     padbefore: usize,
                     bytestodrop: usize,
                     f: F
                     ) -> (Vec<u8>, T) 
    where F: Fn(*mut u8, *const u8, c_ulonglong) -> T {
    let mut dst = Vec::with_capacity(buf.len() + padbefore);
    for _ in (0..padbefore) {
        dst.push(0);
    }
    dst.push_all(buf);
    let pdst = dst.as_mut_ptr();
    let psrc = dst.as_ptr();
    let res = f(pdst, psrc, dst.len() as c_ulonglong);
    (dst.into_iter().skip(bytestodrop).collect(), res)
}

macro_rules! newtype_clone (($newtype:ident) => (
        impl Clone for $newtype {
            fn clone(&self) -> $newtype {
                let &$newtype(v) = self;
                $newtype(v)
            }
        }

        ));

macro_rules! newtype_drop (($newtype:ident) => (
        impl Drop for $newtype {
            fn drop(&mut self) {
                let &mut $newtype(ref mut v) = self;
                unsafe {
                    volatile_set_memory(v.as_mut_ptr(), 0, v.len());
                }
            }
        }
        ));

macro_rules! newtype_impl (($newtype:ident, $len:expr) => (
    impl $newtype {
        /**
         * `from_slice()` creates an object from a byte slice
         *
         * This function will fail and return None if the length of
         * the byte-slice isn't equal to the length of the object
         */
        pub fn from_slice(bs: &[u8]) -> Option<$newtype> {
            if bs.len() != $len {
                return None
            }
            let mut n = $newtype([0; $len]);
            {
                let $newtype(ref mut b) = n;
                for (bi, &bsi) in b.iter_mut().zip(bs.iter()) {
                    *bi = bsi
                }
            }
            Some(n)
        }
        /**
         * `as_slice()` returns a byte slice containing the object contents
         * 
         * WARNING: it might be tempting to do comparisons on objects by
         * using `x.as_slice() == y.as_slice()`. This will open up for
         * timing attacks when comparing for example authenticator
         * tags. Because of this only use the comparison functions
         * exposed by the sodiumoxide API.
         */
        pub fn as_slice(&self) -> &[u8] {
            let &$newtype(ref bs) = self;
            bs.as_slice()
        }
        /**
         * `as_mut_slice()` returns a mutable byte slice containing the object
         * contents
         *
         * WARNING: it might be tempting to do comparisons on objects by
         * using `x.as_mut_slice() == y.as_mut_slice()`. This will
         * open up for timing attacks when comparing for example
         * authenticator tags. Because of this only use the comparison
         * functions exposed by the sodiumoxide API.
         */
        pub fn as_mut_slice(&mut self) -> &mut [u8] {
            let &mut $newtype(ref mut bs) = self;
            bs.as_mut_slice()
        }
    }
    ));
