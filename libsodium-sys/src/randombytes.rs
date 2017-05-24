// randombytes.h

extern {
    pub fn randombytes_buf(buf: *mut u8,
                           size: size_t);
    pub fn randombytes_uniform(upper_bound: u32) -> u32;
}
