use std::libc::{c_ulonglong};
use std::vec::{with_capacity, append};
use std::vec::raw::{to_mut_ptr, to_ptr};

#[doc(hidden)]
pub fn marshal<T>(buf: &[u8],
                  padbefore: uint,
                  bytestodrop: uint,
                  f: &fn(*mut u8, *u8, c_ulonglong) -> T
                 ) -> (~[u8], T) {
    let mut dst = with_capacity(buf.len() + padbefore);
    for _ in range(0, padbefore) {
        dst.push(0);
    }
    dst = append(dst, buf);
    let pdst = to_mut_ptr(dst);
    let psrc = to_ptr(dst);
    let res = f(pdst, psrc, dst.len() as c_ulonglong);
    (dst.move_iter().skip(bytestodrop).collect(), res)
}
