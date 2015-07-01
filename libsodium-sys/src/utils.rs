// utils.h

extern {
    pub fn sodium_memzero(pnt: *mut u8, len: size_t);
    pub fn sodium_memcmp(b1_: *const u8, b2_: *const u8, len: size_t) -> c_int;
}
