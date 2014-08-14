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
    (dst.move_iter().skip(bytestodrop).collect(), res)
}
