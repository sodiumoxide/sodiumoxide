use ffi::crypto_generichash_BYTES_MAX;

/// Digest-structure
///
/// This structure contains a fixed sized array as a buffer and a length to
/// represent dynamic sized digest outputs.
#[derive(Clone)]
pub struct Digest {
    pub(super) len: usize,
    pub(super) data: [u8; crypto_generichash_BYTES_MAX],
}

impl ::std::cmp::PartialEq for Digest {
    fn eq(&self, other: &Digest) -> bool {
        use utils::memcmp;
        if other.len != self.len {
            return false;
        }
        memcmp(self.as_ref(), self.as_ref())
    }
}

impl ::std::cmp::Eq for Digest {}

impl AsRef<[u8]> for Digest {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        &self.data[0..self.len]
    }
}

impl ::std::cmp::PartialOrd for Digest {
    #[inline]
    fn partial_cmp(&self, other: &Digest) -> Option<::std::cmp::Ordering> {
        ::std::cmp::PartialOrd::partial_cmp(self.as_ref(), other.as_ref())
    }

    #[inline]
    fn lt(&self, other: &Digest) -> bool {
        ::std::cmp::PartialOrd::lt(self.as_ref(), other.as_ref())
    }

    #[inline]
    fn le(&self, other: &Digest) -> bool {
        ::std::cmp::PartialOrd::le(self.as_ref(), other.as_ref())
    }

    #[inline]
    fn ge(&self, other: &Digest) -> bool {
        ::std::cmp::PartialOrd::ge(self.as_ref(), other.as_ref())
    }

    #[inline]
    fn gt(&self, other: &Digest) -> bool {
        ::std::cmp::PartialOrd::gt(self.as_ref(), other.as_ref())
    }
}

impl ::std::cmp::Ord for Digest {
    #[inline]
    fn cmp(&self, other: &Digest) -> ::std::cmp::Ordering {
        ::std::cmp::Ord::cmp(self.as_ref(), other.as_ref())
    }
}

impl ::std::hash::Hash for Digest {
    fn hash<H: ::std::hash::Hasher>(&self, state: &mut H) {
        ::std::hash::Hash::hash(self.as_ref(), state)
    }
}

/// Allows a user to access the byte contents of an object as a slice.
///
/// WARNING: it might be tempting to do comparisons on objects
/// by using `x[a..b] == y[a..b]`. This will open up for timing attacks
/// when comparing for example authenticator tags. Because of this only
/// use the comparison functions exposed by the sodiumoxide API.
impl ::std::ops::Index<::std::ops::Range<usize>> for Digest {
    type Output = [u8];
    fn index(&self, _index: ::std::ops::Range<usize>) -> &[u8] {
        self.as_ref().index(_index)
    }
}

/// Allows a user to access the byte contents of an object as a slice.
///
/// WARNING: it might be tempting to do comparisons on objects
/// by using `x[..b] == y[..b]`. This will open up for timing attacks
/// when comparing for example authenticator tags. Because of this only
/// use the comparison functions exposed by the sodiumoxide API.
impl ::std::ops::Index<::std::ops::RangeTo<usize>> for Digest {
    type Output = [u8];
    fn index(&self, _index: ::std::ops::RangeTo<usize>) -> &[u8] {
        self.as_ref().index(_index)
    }
}

/// Allows a user to access the byte contents of an object as a slice.
///
/// WARNING: it might be tempting to do comparisons on objects
/// by using `x[a..] == y[a..]`. This will open up for timing attacks
/// when comparing for example authenticator tags. Because of this only
/// use the comparison functions exposed by the sodiumoxide API.
impl ::std::ops::Index<::std::ops::RangeFrom<usize>> for Digest {
    type Output = [u8];
    fn index(&self, _index: ::std::ops::RangeFrom<usize>) -> &[u8] {
        self.as_ref().index(_index)
    }
}

/// Allows a user to access the byte contents of an object as a slice.
///
/// WARNING: it might be tempting to do comparisons on objects
/// by using `x[] == y[]`. This will open up for timing attacks
/// when comparing for example authenticator tags. Because of this only
/// use the comparison functions exposed by the sodiumoxide API.
impl ::std::ops::Index<::std::ops::RangeFull> for Digest {
    type Output = [u8];
    fn index(&self, _index: ::std::ops::RangeFull) -> &[u8] {
        self.as_ref().index(_index)
    }
}

impl ::std::fmt::Debug for Digest {
    fn fmt(&self, formatter: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        write!(formatter, "Digest({:?})", &self[..])
    }
}