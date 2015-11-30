//! Common traits for types in sodiumoxide

/// The `FromSlice` trait is used to convert from a byte slice to
/// an implementing type.
pub trait FromSlice : Sized {
    /// `from_slice()` creates an object from a byte slice
    ///
    /// This function will fail and return None if the length of
    /// the byte-slice isn't equal to the length of the object
    fn from_slice(bs: &[u8]) -> Option<Self>;
}
