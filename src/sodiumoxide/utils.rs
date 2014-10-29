#![macro_escape]

use libc::c_ulonglong;

#[doc(hidden)]
pub fn marshal<T>(buf: &[u8],
                  padbefore: uint,
                  bytestodrop: uint,
                  f: |*mut u8, *const u8, c_ulonglong| -> T
                 ) -> (Vec<u8>, T) {
    let mut dst = Vec::with_capacity(buf.len() + padbefore);
    for _ in range(0, padbefore) {
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

        ))

macro_rules! newtype_drop (($newtype:ident) => (
        impl Drop for $newtype {
            fn drop(&mut self) {
                let &$newtype(ref mut v) = self;
                unsafe {
                    volatile_set_memory(v.as_mut_ptr(), 0, v.len());
                }
            }
        }
        ))
