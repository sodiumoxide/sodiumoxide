// crypto_verify_32.h

extern {
    pub fn crypto_verify_32(x: *const u8, y: *const u8) -> c_int;
}