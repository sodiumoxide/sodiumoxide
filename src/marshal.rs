use libc::c_ulonglong;

#[doc(hidden)]
pub fn marshal<T, F>(buf: &[u8],
                     padbefore: usize,
                     bytestodrop: usize,
                     f: F
                     ) -> (Vec<u8>, T)
    where F: Fn(*mut u8, *const u8, c_ulonglong) -> T {
    let mut dst = Vec::with_capacity(buf.len() + padbefore);
    dst.resize(padbefore, 0u8);
    dst.extend_from_slice(&buf[..]);
    let pdst = dst.as_mut_ptr();
    let psrc = dst.as_ptr();
    let res = f(pdst, psrc, dst.len() as c_ulonglong);
    dst.drain(..bytestodrop);
    (dst, res)
}
