#![macro_escape]

macro_rules! byte_wrapper_impl(($name:ident, $size:ident) => (
    impl $name {
        /**
         * Create an instance from a slice of bytes.  Returns None if the input
         * slice is of the incorrect size.
         */
        pub fn from_slice(data: &[u8]) -> Option<$name> {
            use std::intrinsics::copy_nonoverlapping_memory;

            if data.len() != $size {
                return None;
            }

            let mut ret = [0, ..$size];
            unsafe {
                copy_nonoverlapping_memory(
                    ret.as_mut_ptr(),
                    data.as_ptr(),
                    data.len()
                );
            }

            Some($name(ret))
        }

        /**
         * Create an instance from a byte slice, without copying any data.
         * Returns an instance with the same lifetime as the input slice, or
         * None if the input slice is the wrong size.
         */
        pub fn from_slice_by_ref<'a>(data: &'a [u8]) -> Option<&'a $name> {
            use std::intrinsics::transmute;

            if data.len() != $size {
                return None;
            }

            Some(unsafe {
                transmute(data.as_ptr())
            })
        }

        /**
         * Borrow this instance as a slice.
         */
        pub fn as_slice(&self) -> &[u8] {
            let &$name(ref data) = self;
            data.as_slice()
        }
    }

))

macro_rules! byte_wrapper_traits(($name:ident, $size:ident) => (
    impl PartialEq for $name {
        fn eq(&self, other: &$name) -> bool {
            use utils::secure_compare;

            secure_compare(self.as_slice(), other.as_slice())
        }
    }

    impl Eq for $name {}

    impl ::std::fmt::Show for $name {
        fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
            self.as_slice().fmt(f)
        }
    }
))

macro_rules! byte_wrapper_helpers(($name:ident, $size:ident) => (
    byte_wrapper_impl!($name, $size)
    byte_wrapper_traits!($name, $size)
))
