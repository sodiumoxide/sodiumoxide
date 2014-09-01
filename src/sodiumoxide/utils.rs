use libc::{c_int, c_ulonglong, c_void};
use libc::types::os::arch::c95::size_t;

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
    (dst.move_iter().skip(bytestodrop).collect(), res)
}

#[link(name = "sodium")]
extern "C" {
    fn sodium_memcmp(b1: *const c_void, b2: *const c_void, len: size_t) -> c_int;
}

pub fn secure_compare(one: &[u8], two: &[u8]) -> bool {
    if one.len() != two.len() {
        return false;
    }

    let r = unsafe {
        sodium_memcmp(
            one.as_ptr() as *const c_void,
            two.as_ptr() as *const c_void,
            one.len() as size_t
        )
    };

    r == 0 as c_int
}
