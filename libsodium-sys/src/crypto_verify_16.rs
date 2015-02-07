// crypto_verify_16.h

extern {
    pub fn crypto_verify_16(x: *const u8, y: *const u8) -> c_int;
}
