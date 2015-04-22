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
                use libc::size_t;
                use ffi;
                let &mut $newtype(ref mut v) = self;
                unsafe {
                    ffi::sodium_memzero(v.as_mut_ptr(), v.len() as size_t);
                }
            }
        }
        ));

macro_rules! newtype_impl (($newtype:ident, $len:expr) => (
    impl $newtype {
        /// `from_slice()` creates an object from a byte slice
        ///
        /// This function will fail and return None if the length of
        /// the byte-slice isn't equal to the length of the object
        pub fn from_slice(bs: &[u8]) -> Option<$newtype> {
            if bs.len() != $len {
                return None;
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
    }
    /// Allows a user to access the byte contents of an object as a slice.
    ///
    /// WARNING: it might be tempting to do comparisons on objects
    /// by using `x[a..b] == y[a..b]`. This will open up for timing attacks
    /// when comparing for example authenticator tags. Because of this only
    /// use the comparison functions exposed by the sodiumoxide API.
    impl Index<Range<usize>> for $newtype {
        type Output = [u8];
        fn index(&self, _index: Range<usize>) -> &[u8] {
            let &$newtype(ref b) = self;
            b.index(_index)
        }
    }
    /// Allows a user to access the byte contents of an object as a slice.
    ///
    /// WARNING: it might be tempting to do comparisons on objects
    /// by using `x[..b] == y[..b]`. This will open up for timing attacks
    /// when comparing for example authenticator tags. Because of this only
    /// use the comparison functions exposed by the sodiumoxide API.
    impl Index<RangeTo<usize>> for $newtype {
        type Output = [u8];
        fn index(&self, _index: RangeTo<usize>) -> &[u8] {
            let &$newtype(ref b) = self;
            b.index(_index)
        }
    }
    /// Allows a user to access the byte contents of an object as a slice.
    ///
    /// WARNING: it might be tempting to do comparisons on objects
    /// by using `x[a..] == y[a..]`. This will open up for timing attacks
    /// when comparing for example authenticator tags. Because of this only
    /// use the comparison functions exposed by the sodiumoxide API.
    impl Index<RangeFrom<usize>> for $newtype {
        type Output = [u8];
        fn index(&self, _index: RangeFrom<usize>) -> &[u8] {
            let &$newtype(ref b) = self;
            b.index(_index)
        }
    }
    /// Allows a user to access the byte contents of an object as a slice.
    ///
    /// WARNING: it might be tempting to do comparisons on objects
    /// by using `x[] == y[]`. This will open up for timing attacks
    /// when comparing for example authenticator tags. Because of this only
    /// use the comparison functions exposed by the sodiumoxide API.
    impl Index<RangeFull> for $newtype {
        type Output = [u8];
        fn index(&self, _index: RangeFull) -> &[u8] {
            let &$newtype(ref b) = self;
            b.index(_index)
        }
    }
    ));
