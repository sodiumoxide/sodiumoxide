// crypto_kx.h

pub const crypto_kx_PUBLICKEYBYTES: usize = 32;
pub const crypto_kx_SECRETKEYBYTES: usize = 32;
pub const crypto_kx_SEEDBYTES: usize = 32;
pub const crypto_kx_SESSIONKEYBYTES: usize = 32;
pub const crypto_kx_PRIMITIVE: &'static str = "x25519blake2b";

extern "C" {
    pub fn crypto_kx_seed_keypair(
        pk: *mut [u8; crypto_kx_PUBLICKEYBYTES],
        sk: *mut [u8; crypto_kx_SECRETKEYBYTES],
        seed: *const [u8; crypto_kx_SEEDBYTES],
    ) -> c_int;

    pub fn crypto_kx_keypair(
        pk: *mut [u8; crypto_kx_PUBLICKEYBYTES],
        sk: *mut [u8; crypto_kx_SECRETKEYBYTES],
    ) -> c_int;

    pub fn crypto_kx_client_session_keys(
        rx: *mut [u8; crypto_kx_SESSIONKEYBYTES],
        tx: *mut [u8; crypto_kx_SESSIONKEYBYTES],
        client_pk: *const [u8; crypto_kx_PUBLICKEYBYTES],
        client_sk: *const [u8; crypto_kx_SECRETKEYBYTES],
        server_pk: *const [u8; crypto_kx_PUBLICKEYBYTES],
    ) -> c_int;

    pub fn crypto_kx_server_session_keys(
        rx: *mut [u8; crypto_kx_SESSIONKEYBYTES],
        tx: *mut [u8; crypto_kx_SESSIONKEYBYTES],
        server_pk: *const [u8; crypto_kx_PUBLICKEYBYTES],
        server_sk: *const [u8; crypto_kx_SECRETKEYBYTES],
        client_pk: *const [u8; crypto_kx_PUBLICKEYBYTES],
    ) -> c_int;

    pub fn crypto_kx_publickeybytes() -> size_t;
    pub fn crypto_kx_secretkeybytes() -> size_t;
    pub fn crypto_kx_seedbytes() -> size_t;
    pub fn crypto_kx_sessionkeybytes() -> size_t;
    pub fn crypto_kx_primitive() -> *const c_char;
}

#[test]
fn test_crypto_kx_publickeybytes() {
    assert!(unsafe { crypto_kx_publickeybytes() } == crypto_kx_PUBLICKEYBYTES)
}

#[test]
fn test_crypto_kx_secretkeybytes() {
    assert!(unsafe { crypto_kx_secretkeybytes() } == crypto_kx_SECRETKEYBYTES)
}

#[test]
fn test_crypto_kx_seedbytes() {
    assert!(unsafe { crypto_kx_seedbytes() } == crypto_kx_SEEDBYTES)
}

#[test]
fn test_crypto_kx_sessionkeybytes() {
    assert!(unsafe { crypto_kx_sessionkeybytes() } == crypto_kx_SESSIONKEYBYTES)
}

#[test]
fn test_crypto_kx_primitive() {
    unsafe {
        let s = crypto_kx_primitive();
        let s = std::ffi::CStr::from_ptr(s).to_bytes();
        assert!(s == crypto_kx_PRIMITIVE.as_bytes());
    }
}
