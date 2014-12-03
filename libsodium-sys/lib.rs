#![allow(non_upper_case_globals)]

extern crate libc;
use libc::{c_int, c_ulonglong, c_char, size_t};

pub const crypto_stream_KEYBYTES : size_t = crypto_stream_xsalsa20_KEYBYTES;
pub const crypto_stream_NONCEBYTES : size_t = crypto_stream_xsalsa20_NONCEBYTES;
pub const crypto_stream_PRIMITIVE : &'static str = "xsalsa20";

pub const crypto_stream_aes128ctr_KEYBYTES : size_t = 16;
pub const crypto_stream_aes128ctr_NONCEBYTES : size_t = 16;
pub const crypto_stream_aes128ctr_BEFORENMBYTES : size_t = 1408;

pub const crypto_stream_chacha20_KEYBYTES : size_t = 32;
pub const crypto_stream_chacha20_NONCEBYTES : size_t = 8;

pub const crypto_stream_salsa20_KEYBYTES : size_t = 32;
pub const crypto_stream_salsa20_NONCEBYTES : size_t = 8;

pub const crypto_stream_salsa2012_KEYBYTES : size_t = 32;
pub const crypto_stream_salsa2012_NONCEBYTES : size_t = 8;

pub const crypto_stream_salsa208_KEYBYTES : size_t = 32;
pub const crypto_stream_salsa208_NONCEBYTES : size_t = 8;

pub const crypto_stream_xsalsa20_KEYBYTES : size_t = 32;
pub const crypto_stream_xsalsa20_NONCEBYTES : size_t = 24;


extern {
  pub fn sodium_init() -> c_int;
  
  pub fn randombytes_buf(buf: *mut u8,
                         size: size_t);

  pub fn crypto_auth_hmacsha512256(a: *mut u8,
                                   m: *const u8,
                                   mlen: c_ulonglong,
                                   k: *const u8) -> c_int;
  pub fn crypto_auth_hmacsha512256_verify(a: *const u8,
                                          m: *const u8,
                                          mlen: c_ulonglong,
                                          k: *const u8) -> c_int;
  pub fn crypto_auth_hmacsha256(a: *mut u8,
                                m: *const u8,
                                mlen: c_ulonglong,
                                k: *const u8) -> c_int;
  pub fn crypto_auth_hmacsha256_verify(a: *const u8,
                                       m: *const u8,
                                       mlen: c_ulonglong,
                                       k: *const u8) -> c_int;
  pub fn crypto_onetimeauth_poly1305(a: *mut u8,
                                     m: *const u8,
                                     mlen: c_ulonglong,
                                     k: *const u8) -> c_int;
  pub fn crypto_onetimeauth_poly1305_verify(a: *const u8,
                                            m: *const u8,
                                            mlen: c_ulonglong,
                                            k: *const u8) -> c_int;

  pub fn crypto_stream_keybytes() -> size_t;
  pub fn crypto_stream_noncebytes() -> size_t;
  pub fn crypto_stream_primitive() -> *const c_char;                                           

  pub fn crypto_stream_aes128ctr(c: *mut u8,
                                 clen: c_ulonglong,
                                 n: *const u8,
                                 k: *const u8) -> c_int;
  pub fn crypto_stream_aes128ctr_xor(c: *mut u8,
                                     m: *const u8,
                                     mlen: c_ulonglong,
                                     n: *const u8,
                                     k: *const u8) -> c_int;
  pub fn crypto_stream_aes128ctr_keybytes() -> size_t;
  pub fn crypto_stream_aes128ctr_noncebytes() -> size_t;
  pub fn crypto_stream_aes128ctr_beforenmbytes() -> size_t;
  
  pub fn crypto_stream_chacha20_keybytes() -> size_t;
  pub fn crypto_stream_chacha20_noncebytes() -> size_t;

  pub fn crypto_stream_salsa20(c: *mut u8,
                               clen: c_ulonglong,
                               n: *const u8,
                               k: *const u8) -> c_int;
  pub fn crypto_stream_salsa20_xor(c: *mut u8,
                                   m: *const u8,
                                   mlen: c_ulonglong,
                                   n: *const u8,
                                   k: *const u8) -> c_int;   
  pub fn crypto_stream_salsa20_keybytes() -> size_t;
  pub fn crypto_stream_salsa20_noncebytes() -> size_t;

  pub fn crypto_stream_salsa208(c: *mut u8,
                                clen: c_ulonglong,
                                n: *const u8,
                                k: *const u8) -> c_int;
  pub fn crypto_stream_salsa208_xor(c: *mut u8,
                                    m: *const u8,
                                    mlen: c_ulonglong,
                                    n: *const u8,
                                    k: *const u8) -> c_int;
  pub fn crypto_stream_salsa208_keybytes() -> size_t;
  pub fn crypto_stream_salsa208_noncebytes() -> size_t;

  pub fn crypto_stream_salsa2012(c: *mut u8,
                                 clen: c_ulonglong,
                                 n: *const u8,
                                 k: *const u8) -> c_int;
  pub fn crypto_stream_salsa2012_xor(c: *mut u8,
                                     m: *const u8,
                                     mlen: c_ulonglong,
                                     n: *const u8,
                                     k: *const u8) -> c_int;
  pub fn crypto_stream_salsa2012_keybytes() -> size_t;
  pub fn crypto_stream_salsa2012_noncebytes() -> size_t;

  pub fn crypto_stream_xsalsa20(c: *mut u8,
                                clen: c_ulonglong,
                                n: *const u8,
                                k: *const u8) -> c_int;
  pub fn crypto_stream_xsalsa20_xor(c: *mut u8,
                                    m: *const u8,
                                    mlen: c_ulonglong,
                                    n: *const u8,
                                    k: *const u8) -> c_int;
  pub fn crypto_stream_xsalsa20_keybytes() -> size_t;
  pub fn crypto_stream_xsalsa20_noncebytes() -> size_t;

  pub fn crypto_hash_sha256(h: *mut u8,
                            m: *const u8,
                            mlen: c_ulonglong) -> c_int;
  pub fn crypto_hash_sha512(h: *mut u8,
                            m: *const u8,
                            mlen: c_ulonglong) -> c_int;

  pub fn crypto_scalarmult_curve25519(q: *mut u8,
                                      n: *const u8,
                                      p: *const u8) -> c_int;
  pub fn crypto_scalarmult_curve25519_base(q: *mut u8,
                                           n: *const u8) -> c_int;

  pub fn crypto_box_curve25519xsalsa20poly1305_keypair(pk: *mut u8,
                                                       sk: *mut u8) -> c_int;
  pub fn crypto_box_curve25519xsalsa20poly1305(c: *mut u8,
                                               m: *const u8,
                                               mlen: c_ulonglong,
                                               n: *const u8,
                                               pk: *const u8,
                                               sk: *const u8) -> c_int;
  pub fn crypto_box_curve25519xsalsa20poly1305_open(m: *mut u8,
                                                    c: *const u8,
                                                    clen: c_ulonglong,
                                                    n: *const u8,
                                                    pk: *const u8,
                                                    sk: *const u8) -> c_int;
  pub fn crypto_box_curve25519xsalsa20poly1305_beforenm(k: *mut u8,
                                                        pk: *const u8,
                                                        sk: *const u8) -> c_int;
  pub fn crypto_box_curve25519xsalsa20poly1305_afternm(c: *mut u8,
                                                       m: *const u8,
                                                       mlen: c_ulonglong,
                                                       n: *const u8,
                                                       k: *const u8) -> c_int;
  pub fn crypto_box_curve25519xsalsa20poly1305_open_afternm(m: *mut u8,
                                                            c: *const u8,
                                                            clen: c_ulonglong,
                                                            n: *const u8,
                                                            k: *const u8) -> c_int;

  pub fn crypto_sign_ed25519_keypair(pk: *mut u8,
                                     sk: *mut u8) -> c_int;
  pub fn crypto_sign_ed25519_seed_keypair(pk: *mut u8,
                                          sk: *mut u8,
                                          seed: *const u8) -> c_int;
  pub fn crypto_sign_ed25519(sm: *mut u8,
                             smlen: *mut c_ulonglong,
                             m: *const u8,
                             mlen: c_ulonglong,
                             sk: *const u8) -> c_int;
  pub fn crypto_sign_ed25519_open(m: *mut u8,
                                  mlen: *mut c_ulonglong,
                                  sm: *const u8,
                                  smlen: c_ulonglong,
                                  pk: *const u8) -> c_int;

  pub fn crypto_sign_edwards25519sha512batch_keypair(pk: *mut u8,
                                                     sk: *mut u8) -> c_int;
  pub fn crypto_sign_edwards25519sha512batch(sm: *mut u8,
                                             smlen: *mut c_ulonglong,
                                             m: *const u8,
                                             mlen: c_ulonglong,
                                             sk: *const u8) -> c_int;
  pub fn crypto_sign_edwards25519sha512batch_open(m: *mut u8,
                                                  mlen: *mut c_ulonglong,
                                                  sm: *const u8,
                                                  smlen: c_ulonglong,
                                                  pk: *const u8) -> c_int;
                     
  pub fn crypto_shorthash_siphash24(h: *mut u8,
                                    m: *const u8,
                                    mlen: c_ulonglong,
                                    k: *const u8) -> c_int;
                                    
  pub fn crypto_verify_16(x: *const u8, y: *const u8) -> c_int;
  pub fn crypto_verify_32(x: *const u8, y: *const u8) -> c_int;

  pub fn crypto_secretbox_xsalsa20poly1305(c: *mut u8,
                                           m: *const u8,
                                           mlen: c_ulonglong,
                                           n: *const u8,
                                           k: *const u8) -> c_int;
  pub fn crypto_secretbox_xsalsa20poly1305_open(m: *mut u8,
                                                c: *const u8,
                                                clen: c_ulonglong,
                                                n: *const u8,
                                                k: *const u8) -> c_int;
}


#[test]
fn test_crypto_stream_keybytes() {
    assert!(unsafe { crypto_stream_keybytes() } == crypto_stream_KEYBYTES)
}
#[test]
fn test_crypto_stream_noncebytes() {
    assert!(unsafe { crypto_stream_noncebytes() } == crypto_stream_NONCEBYTES)
}
#[test]
fn test_crypto_stream_primitive() {
    let s = unsafe {
        std::c_str::CString::new(crypto_stream_primitive(), false)
    };
    assert!(s.as_bytes_no_nul() == crypto_stream_PRIMITIVE.as_bytes());
}

#[test]
fn test_crypto_stream_aes128ctr_keybytes() {
    assert!(unsafe { crypto_stream_aes128ctr_keybytes() } == crypto_stream_aes128ctr_KEYBYTES)
}
#[test]
fn test_crypto_stream_aes128ctr_noncebytes() {
    assert!(unsafe { crypto_stream_aes128ctr_noncebytes() } == crypto_stream_aes128ctr_NONCEBYTES)
}
#[test]
fn test_crypto_stream_aes128ctr_beforenmbytes() {
    assert!(unsafe { crypto_stream_aes128ctr_beforenmbytes() } == crypto_stream_aes128ctr_BEFORENMBYTES)
}

#[test]
fn test_crypto_stream_chacha20_keybytes() {
    assert!(unsafe { crypto_stream_chacha20_keybytes() } == crypto_stream_chacha20_KEYBYTES)
}
#[test]
fn test_crypto_stream_chacha20_noncebytes() {
    assert!(unsafe { crypto_stream_chacha20_noncebytes() } == crypto_stream_chacha20_NONCEBYTES)
}

#[test]
fn test_crypto_stream_salsa20_keybytes() {
    assert!(unsafe { crypto_stream_salsa20_keybytes() } == crypto_stream_salsa20_KEYBYTES)
}
#[test]
fn test_crypto_stream_salsa20_noncebytes() {
    assert!(unsafe { crypto_stream_salsa20_noncebytes() } == crypto_stream_salsa20_NONCEBYTES)
}

#[test]
fn test_crypto_stream_salsa208_keybytes() {
    assert!(unsafe { crypto_stream_salsa208_keybytes() } == crypto_stream_salsa208_KEYBYTES)
}
#[test]
fn test_crypto_stream_salsa208_noncebytes() {
    assert!(unsafe { crypto_stream_salsa208_noncebytes() } == crypto_stream_salsa208_NONCEBYTES)
}

#[test]
fn test_crypto_stream_salsa2012_keybytes() {
    assert!(unsafe { crypto_stream_salsa2012_keybytes() } == crypto_stream_salsa2012_KEYBYTES)
}
#[test]
fn test_crypto_stream_salsa2012_noncebytes() {
    assert!(unsafe { crypto_stream_salsa2012_noncebytes() } == crypto_stream_salsa2012_NONCEBYTES)
}

#[test]
fn test_crypto_stream_xsalsa20_keybytes() {
    assert!(unsafe { crypto_stream_xsalsa20_keybytes() } == crypto_stream_xsalsa20_KEYBYTES)
}
#[test]
fn test_crypto_stream_xsalsa20_noncebytes() {
    assert!(unsafe { crypto_stream_xsalsa20_noncebytes() } == crypto_stream_xsalsa20_NONCEBYTES)
}
