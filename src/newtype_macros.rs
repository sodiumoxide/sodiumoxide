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
    impl ::std::cmp::PartialEq for $newtype {
        fn eq(&self, &$newtype(ref other): &$newtype) -> bool {
            use crypto::verify::safe_memcmp;
            let &$newtype(ref this) = self;
            safe_memcmp(this, other)
        }
    }
    impl ::std::cmp::Eq for $newtype {}
    impl rustc_serialize::Encodable for $newtype {
        fn encode<E: rustc_serialize::Encoder>(&self, encoder: &mut E)
                -> Result<(), E::Error> {
            encoder.emit_seq($len, |encoder| {
                for (i, e) in self[..].iter().enumerate() {
                    try!(encoder.emit_seq_elt(i, |encoder| e.encode(encoder)))
                }
                Ok(())
            })
        }
    }
    impl rustc_serialize::Decodable for $newtype {
        fn decode<D: rustc_serialize::Decoder>(decoder: &mut D)
                -> Result<$newtype, D::Error> {
            decoder.read_seq(|decoder, len| {
                if len != $len {
                    return Err(decoder.error(
                        &format!("Expecting array of length: {}, but found {}",
                                 $len, len)));
                }
                let mut res = $newtype([0; $len]);
                {
                    let $newtype(ref mut arr) = res;
                    for (i, val) in arr.iter_mut().enumerate() {
                        *val = try!(decoder.read_seq_elt(i,
                            |decoder| rustc_serialize::Decodable::decode(decoder)));
                    }
                }
                Ok(res)
            })
        }
    }
    /// Allows a user to access the byte contents of an object as a slice.
    ///
    /// WARNING: it might be tempting to do comparisons on objects
    /// by using `x[a..b] == y[a..b]`. This will open up for timing attacks
    /// when comparing for example authenticator tags. Because of this only
    /// use the comparison functions exposed by the sodiumoxide API.
    impl ::std::ops::Index<::std::ops::Range<usize>> for $newtype {
        type Output = [u8];
        fn index(&self, _index: ::std::ops::Range<usize>) -> &[u8] {
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
    impl ::std::ops::Index<::std::ops::RangeTo<usize>> for $newtype {
        type Output = [u8];
        fn index(&self, _index: ::std::ops::RangeTo<usize>) -> &[u8] {
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
    impl ::std::ops::Index<::std::ops::RangeFrom<usize>> for $newtype {
        type Output = [u8];
        fn index(&self, _index: ::std::ops::RangeFrom<usize>) -> &[u8] {
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
    impl ::std::ops::Index<::std::ops::RangeFull> for $newtype {
        type Output = [u8];
        fn index(&self, _index: ::std::ops::RangeFull) -> &[u8] {
            let &$newtype(ref b) = self;
            b.index(_index)
        }
    }
    impl ::std::fmt::Debug for $newtype  {
        fn fmt(&self,
               formatter: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
            write!(formatter, "{}({:?})", stringify!($newtype), &self[..])
        }
    }
    ));

macro_rules! non_secret_newtype_impl (($newtype:ident) => (
    impl AsRef<[u8]> for $newtype {
        #[inline]
        fn as_ref(&self) -> &[u8] {
            &self[..]
        }
    }
    impl ::std::cmp::PartialOrd for $newtype {
        #[inline]
        fn partial_cmp(&self,
                       other: &$newtype) -> Option<::std::cmp::Ordering> {
            ::std::cmp::PartialOrd::partial_cmp(self.as_ref(), other.as_ref())
        }
        #[inline]
        fn lt(&self, other: &$newtype) -> bool {
            ::std::cmp::PartialOrd::lt(self.as_ref(), other.as_ref())
        }
        #[inline]
        fn le(&self, other: &$newtype) -> bool {
            ::std::cmp::PartialOrd::le(self.as_ref(), other.as_ref())
        }
        #[inline]
        fn ge(&self, other: &$newtype) -> bool {
            ::std::cmp::PartialOrd::ge(self.as_ref(), other.as_ref())
        }
        #[inline]
        fn gt(&self, other: &$newtype) -> bool {
            ::std::cmp::PartialOrd::gt(self.as_ref(), other.as_ref())
        }
    }
    impl ::std::cmp::Ord for $newtype {
        #[inline]
        fn cmp(&self, other: &$newtype) -> ::std::cmp::Ordering {
            ::std::cmp::Ord::cmp(self.as_ref(), other.as_ref())
        }
    }
    impl ::std::hash::Hash for $newtype {
        fn hash<H: ::std::hash::Hasher>(&self, state: &mut H) {
            ::std::hash::Hash::hash(self.as_ref(), state)
        }
    }
    ));
