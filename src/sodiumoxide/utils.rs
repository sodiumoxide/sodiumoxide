use std::libc::c_ulonglong;
use std::slice::{with_capacity, append};

#[doc(hidden)]
pub fn marshal<T>(buf: &[u8],
                  padbefore: uint,
                  bytestodrop: uint,
                  f: proc (*mut u8, *u8, c_ulonglong) -> T
                 ) -> (~[u8], T) {
    let mut dst = with_capacity(buf.len() + padbefore);
    for _ in range(0, padbefore) {
        dst.push(0);
    }
    dst = append(dst, buf);
    let pdst = dst.as_mut_ptr();
    let psrc = dst.as_ptr();
    let res = f(pdst, psrc, dst.len() as c_ulonglong);
    (dst.move_iter().skip(bytestodrop).collect(), res)
}
