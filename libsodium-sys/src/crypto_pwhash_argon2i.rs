// crypto_pwhash_argon2i.h

pub const crypto_pwhash_argon2i_ALG_ARGON2I13: i32 = 1;
pub const crypto_pwhash_argon2i_SALTBYTES: usize = 16;
pub const crypto_pwhash_argon2i_STRBYTES: usize = 128;
pub const crypto_pwhash_argon2i_STRPREFIX: &'static str =
    "$argon2i$";
pub const crypto_pwhash_argon2i_OPSLIMIT_INTERACTIVE: usize = 4;
pub const crypto_pwhash_argon2i_MEMLIMIT_INTERACTIVE: usize =
    33554432;
pub const crypto_pwhash_argon2i_OPSLIMIT_MODERATE: usize = 6;
pub const crypto_pwhash_argon2i_MEMLIMIT_MODERATE: usize =
    134217728;
pub const crypto_pwhash_argon2i_OPSLIMIT_SENSITIVE: usize = 8;
pub const crypto_pwhash_argon2i_MEMLIMIT_SENSITIVE: usize =
    536870912;


extern {
    pub fn crypto_pwhash_argon2i_alg_argon2i13() -> c_int;
    pub fn crypto_pwhash_argon2i_saltbytes() -> size_t;
    pub fn crypto_pwhash_argon2i_strbytes() -> size_t;
    pub fn crypto_pwhash_argon2i_strprefix() -> *const c_char;
    pub fn crypto_pwhash_argon2i_opslimit_interactive() ->
        size_t;
    pub fn crypto_pwhash_argon2i_memlimit_interactive() ->
        size_t;
    pub fn crypto_pwhash_argon2i_opslimit_moderate() -> size_t;
    pub fn crypto_pwhash_argon2i_memlimit_moderate() -> size_t;
    pub fn crypto_pwhash_argon2i_opslimit_sensitive() -> size_t;
    pub fn crypto_pwhash_argon2i_memlimit_sensitive() -> size_t;
    pub fn crypto_pwhash_argon2i(
        out: *mut u8,
        outlen: c_ulonglong,
        passwd: *const u8,
        passwdlen: c_ulonglong,
        salt: *const [u8; crypto_pwhash_argon2i_SALTBYTES],
        opslimit: c_ulonglong,
        memlimit: size_t,
        alg: c_int) -> c_int;
    pub fn crypto_pwhash_argon2i_str(
        out: *mut [u8; crypto_pwhash_argon2i_STRBYTES],
        passwd: *const u8,
        passwdlen: c_ulonglong,
        opslimit: c_ulonglong,
        memlimit: size_t) -> c_int;
    pub fn crypto_pwhash_argon2i_str_verify(
        str_: *const [u8; crypto_pwhash_argon2i_STRBYTES],
        passwd: *const u8,
        passwdlen: c_ulonglong) -> c_int;
}


#[test]
fn test_crypto_pwhash_argon2i_alg_argon2i13() {
    assert!(unsafe {
        crypto_pwhash_argon2i_alg_argon2i13() as i32
    } == crypto_pwhash_argon2i_ALG_ARGON2I13)
}
#[test]
fn test_crypto_pwhash_argon2i_saltbytes() {
    assert!(unsafe {
        crypto_pwhash_argon2i_saltbytes() as usize
    } == crypto_pwhash_argon2i_SALTBYTES)
}
#[test]
fn test_crypto_pwhash_argon2i_strbytes() {
    assert!(unsafe {
        crypto_pwhash_argon2i_strbytes() as usize
    } == crypto_pwhash_argon2i_STRBYTES)
}
#[test]
fn test_crypto_pwhash_argon2i_opslimit_interactive() {
    assert!(unsafe {
        crypto_pwhash_argon2i_opslimit_interactive() as usize
    } == crypto_pwhash_argon2i_OPSLIMIT_INTERACTIVE)
}
#[test]
fn test_crypto_pwhash_argon2i_memlimit_interactive() {
    assert!(unsafe {
        crypto_pwhash_argon2i_memlimit_interactive() as usize
    } == crypto_pwhash_argon2i_MEMLIMIT_INTERACTIVE)
}
#[test]
fn test_crypto_pwhash_argon2i_opslimit_moderate() {
    assert!(unsafe {
        crypto_pwhash_argon2i_opslimit_moderate() as usize
    } == crypto_pwhash_argon2i_OPSLIMIT_MODERATE)
}
#[test]
fn test_crypto_pwhash_argon2i_memlimit_moderate() {
    assert!(unsafe {
        crypto_pwhash_argon2i_memlimit_moderate() as usize
    } == crypto_pwhash_argon2i_MEMLIMIT_MODERATE)
}
#[test]
fn test_crypto_pwhash_argon2i_opslimit_sensitive() {
    assert!(unsafe {
        crypto_pwhash_argon2i_opslimit_sensitive() as usize
    } == crypto_pwhash_argon2i_OPSLIMIT_SENSITIVE)
}
#[test]
fn test_crypto_pwhash_argon2i_memlimit_sensitive() {
    assert!(unsafe {
        crypto_pwhash_argon2i_memlimit_sensitive() as usize
    } == crypto_pwhash_argon2i_MEMLIMIT_SENSITIVE)
}
#[test]
fn test_crypto_pwhash_argon2i_strprefix() {
    unsafe {
         let s = crypto_pwhash_argon2i_strprefix();
         let s = std::ffi::CStr::from_ptr(s).to_bytes();
        assert!(s ==
                crypto_pwhash_argon2i_STRPREFIX.as_bytes());
    }
}
#[test]
fn test_crypto_pwhash_argon2i_str() {
    let password = "Correct Horse Battery Staple";
    let mut hashed_password =
        [0; crypto_pwhash_argon2i_STRBYTES];
    let ret_hash = unsafe {
        crypto_pwhash_argon2i_str(
            &mut hashed_password,
            password.as_ptr(),
            password.len() as c_ulonglong,
            crypto_pwhash_argon2i_OPSLIMIT_INTERACTIVE
                as c_ulonglong,
            crypto_pwhash_argon2i_MEMLIMIT_INTERACTIVE
                as size_t)
    };
    assert!(ret_hash == 0);
    let ret_verify = unsafe {
        crypto_pwhash_argon2i_str_verify(
            &hashed_password,
            password.as_ptr(),
            password.len() as c_ulonglong)
    };
    assert!(ret_verify == 0);
}
