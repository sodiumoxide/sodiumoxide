// crypto_pwhash_argon2id.h

pub const crypto_pwhash_argon2id_ALG_ARGON2ID13: i32 = 2;
pub const crypto_pwhash_argon2id_SALTBYTES: usize = 16;
pub const crypto_pwhash_argon2id_STRBYTES: usize = 128;
pub const crypto_pwhash_argon2id_STRPREFIX: &'static str =
    "$argon2id$";
pub const crypto_pwhash_argon2id_OPSLIMIT_INTERACTIVE: usize = 2;
pub const crypto_pwhash_argon2id_MEMLIMIT_INTERACTIVE: usize =
    67108864;
pub const crypto_pwhash_argon2id_OPSLIMIT_MODERATE: usize = 3;
pub const crypto_pwhash_argon2id_MEMLIMIT_MODERATE: usize =
    268435456;
pub const crypto_pwhash_argon2id_OPSLIMIT_SENSITIVE: usize = 4;
pub const crypto_pwhash_argon2id_MEMLIMIT_SENSITIVE: usize =
    1073741824;


extern {
    pub fn crypto_pwhash_argon2id_alg_argon2id13() -> c_int;
    pub fn crypto_pwhash_argon2id_saltbytes() -> size_t;
    pub fn crypto_pwhash_argon2id_strbytes() -> size_t;
    pub fn crypto_pwhash_argon2id_strprefix() -> *const c_char;
    pub fn crypto_pwhash_argon2id_opslimit_interactive() ->
        size_t;
    pub fn crypto_pwhash_argon2id_memlimit_interactive() ->
        size_t;
    pub fn crypto_pwhash_argon2id_opslimit_moderate() -> size_t;
    pub fn crypto_pwhash_argon2id_memlimit_moderate() -> size_t;
    pub fn crypto_pwhash_argon2id_opslimit_sensitive() -> size_t;
    pub fn crypto_pwhash_argon2id_memlimit_sensitive() -> size_t;
    pub fn crypto_pwhash_argon2id(
        out: *mut u8,
        outlen: c_ulonglong,
        passwd: *const u8,
        passwdlen: c_ulonglong,
        salt: *const [u8; crypto_pwhash_argon2id_SALTBYTES],
        opslimit: c_ulonglong,
        memlimit: size_t,
		alg: c_int) -> c_int;
    pub fn crypto_pwhash_argon2id_str(
        out: *mut [u8; crypto_pwhash_argon2id_STRBYTES],
        passwd: *const u8,
        passwdlen: c_ulonglong,
        opslimit: c_ulonglong,
        memlimit: size_t) -> c_int;
    pub fn crypto_pwhash_argon2id_str_verify(
        str_: *const [u8; crypto_pwhash_argon2id_STRBYTES],
        passwd: *const u8,
        passwdlen: c_ulonglong) -> c_int;
}


#[test]
fn test_crypto_pwhash_argon2id_alg_argon2id13() {
    assert!(unsafe {
        crypto_pwhash_argon2id_alg_argon2id13() as i32
    } == crypto_pwhash_argon2id_ALG_ARGON2ID13)
}
#[test]
fn test_crypto_pwhash_argon2id_saltbytes() {
    assert!(unsafe {
        crypto_pwhash_argon2id_saltbytes() as usize
    } == crypto_pwhash_argon2id_SALTBYTES)
}
#[test]
fn test_crypto_pwhash_argon2id_strbytes() {
    assert!(unsafe {
        crypto_pwhash_argon2id_strbytes() as usize
    } == crypto_pwhash_argon2id_STRBYTES)
}
#[test]
fn test_crypto_pwhash_argon2id_opslimit_interactive() {
    assert!(unsafe {
        crypto_pwhash_argon2id_opslimit_interactive() as usize
    } == crypto_pwhash_argon2id_OPSLIMIT_INTERACTIVE)
}
#[test]
fn test_crypto_pwhash_argon2id_memlimit_interactive() {
    assert!(unsafe {
        crypto_pwhash_argon2id_memlimit_interactive() as usize
    } == crypto_pwhash_argon2id_MEMLIMIT_INTERACTIVE)
}
#[test]
fn test_crypto_pwhash_argon2id_opslimit_moderate() {
    assert!(unsafe {
        crypto_pwhash_argon2id_opslimit_moderate() as usize
    } == crypto_pwhash_argon2id_OPSLIMIT_MODERATE)
}
#[test]
fn test_crypto_pwhash_argon2id_memlimit_moderate() {
    assert!(unsafe {
        crypto_pwhash_argon2id_memlimit_moderate() as usize
    } == crypto_pwhash_argon2id_MEMLIMIT_MODERATE)
}
#[test]
fn test_crypto_pwhash_argon2id_opslimit_sensitive() {
    assert!(unsafe {
        crypto_pwhash_argon2id_opslimit_sensitive() as usize
    } == crypto_pwhash_argon2id_OPSLIMIT_SENSITIVE)
}
#[test]
fn test_crypto_pwhash_argon2id_memlimit_sensitive() {
    assert!(unsafe {
        crypto_pwhash_argon2id_memlimit_sensitive() as usize
    } == crypto_pwhash_argon2id_MEMLIMIT_SENSITIVE)
}
#[test]
fn test_crypto_pwhash_argon2id_strprefix() {
    unsafe {
         let s = crypto_pwhash_argon2id_strprefix();
         let s = std::ffi::CStr::from_ptr(s).to_bytes();
        assert!(s ==
                crypto_pwhash_argon2id_STRPREFIX.as_bytes());
    }
}
#[test]
fn test_crypto_pwhash_argon2id_str() {
    let password = "Correct Horse Battery Staple";
    let mut hashed_password =
        [0; crypto_pwhash_argon2id_STRBYTES];
    let ret_hash = unsafe {
        crypto_pwhash_argon2id_str(
            &mut hashed_password,
            password.as_ptr(),
            password.len() as c_ulonglong,
			16, 8192)
    };
    assert!(ret_hash == 0);
    let ret_verify = unsafe {
        crypto_pwhash_argon2id_str_verify(
            &hashed_password,
            password.as_ptr(),
            password.len() as c_ulonglong)
    };
    assert!(ret_verify == 0);
}
#[test]
fn test_crypto_pwhash_argon2id() {
    let password = "password";
    let salt = b"Let's just dance";
    let mut buf = [0u8; 32];
    let expected = [0x15, 0x49, 0xeb, 0xb9, 0x32, 0xe1, 0x13, 0x0e,
                    0xcf, 0x39, 0x29, 0xa1, 0x18, 0x43, 0x7a, 0x0a,
                    0x56, 0xeb, 0xbc, 0xc4, 0x8b, 0xe8, 0x17, 0x83,
                    0x08, 0x62, 0xfa, 0x75, 0xb5, 0x61, 0x90, 0x47];
    unsafe {
        crypto_pwhash_argon2id(buf.as_mut_ptr(),
                               buf.len() as c_ulonglong,
                               password.as_ptr(),
                               password.len() as c_ulonglong,
                               salt as *const [u8; 16],
                               16, 8192,
                               crypto_pwhash_argon2id_ALG_ARGON2ID13);
    }
    assert!(buf == expected);
}
