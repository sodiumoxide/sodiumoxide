#![allow(non_upper_case_globals)]

#[allow(unstable)]
extern crate libc;
use libc::{c_int, c_ulonglong, c_char, size_t};


// aead
pub const crypto_aead_chacha20poly1305_KEYBYTES: size_t = 32;
pub const crypto_aead_chacha20poly1305_NSECBYTES: size_t = 0;
pub const crypto_aead_chacha20poly1305_NPUBBYTES: size_t = 8;
pub const crypto_aead_chacha20poly1305_ABYTES: size_t = 16;


// stream
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


// auth
pub const crypto_auth_BYTES : size_t = crypto_auth_hmacsha512256_BYTES;
pub const crypto_auth_KEYBYTES : size_t = crypto_auth_hmacsha512256_KEYBYTES;
pub const crypto_auth_PRIMITIVE : &'static str = "hmacsha512256";

pub const crypto_auth_hmacsha256_BYTES : size_t = 32;
pub const crypto_auth_hmacsha256_KEYBYTES : size_t = 32;

pub const crypto_auth_hmacsha512_BYTES : size_t = 64;
pub const crypto_auth_hmacsha512_KEYBYTES : size_t = 32;

pub const crypto_auth_hmacsha512256_BYTES : size_t = 32;
pub const crypto_auth_hmacsha512256_KEYBYTES : size_t = 32;


// onetimeauth
pub const crypto_onetimeauth_BYTES : size_t = crypto_onetimeauth_poly1305_BYTES;
pub const crypto_onetimeauth_KEYBYTES : size_t = crypto_onetimeauth_poly1305_KEYBYTES;
pub const crypto_onetimeauth_PRIMITIVE : &'static str =  "poly1305";

pub const crypto_onetimeauth_poly1305_BYTES : size_t = 16;
pub const crypto_onetimeauth_poly1305_KEYBYTES : size_t = 32;


// hash
pub const crypto_hash_BYTES: size_t = crypto_hash_sha512_BYTES;
pub const crypto_hash_PRIMITIVE: &'static str = "sha512";

pub const crypto_hash_sha256_BYTES: size_t =  32;

pub const crypto_hash_sha512_BYTES: size_t = 64;


// box
pub const crypto_box_curve25519xsalsa20poly1305_SEEDBYTES: size_t = 32;
pub const crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES: size_t = 32;
pub const crypto_box_curve25519xsalsa20poly1305_SECRETKEYBYTES: size_t = 32;
pub const crypto_box_curve25519xsalsa20poly1305_BEFORENMBYTES: size_t = 32;
pub const crypto_box_curve25519xsalsa20poly1305_NONCEBYTES: size_t = 24;
pub const crypto_box_curve25519xsalsa20poly1305_ZEROBYTES: size_t = 32;
pub const crypto_box_curve25519xsalsa20poly1305_BOXZEROBYTES: size_t = 16;
pub const crypto_box_curve25519xsalsa20poly1305_MACBYTES: size_t =
    crypto_box_curve25519xsalsa20poly1305_ZEROBYTES -
    crypto_box_curve25519xsalsa20poly1305_BOXZEROBYTES;


// scalarmult
pub const crypto_scalarmult_curve25519_BYTES: size_t = 32;
pub const crypto_scalarmult_curve25519_SCALARBYTES: size_t = 32;


// sign
pub const crypto_sign_ed25519_BYTES: size_t = 64;
pub const crypto_sign_ed25519_SEEDBYTES: size_t = 32;
pub const crypto_sign_ed25519_PUBLICKEYBYTES: size_t = 32;
pub const crypto_sign_ed25519_SECRETKEYBYTES: size_t = 64;

pub const crypto_sign_edwards25519sha512batch_BYTES: size_t = 64;
pub const crypto_sign_edwards25519sha512batch_PUBLICKEYBYTES: size_t = 32;
pub const crypto_sign_edwards25519sha512batch_SECRETKEYBYTES: size_t = 64;


// shorthash
pub const crypto_shorthash_siphash24_BYTES: size_t = 8;
pub const crypto_shorthash_siphash24_KEYBYTES: size_t = 16;


// secretbox
pub const crypto_secretbox_xsalsa20poly1305_KEYBYTES: size_t = 32;
pub const crypto_secretbox_xsalsa20poly1305_NONCEBYTES: size_t = 24;
pub const crypto_secretbox_xsalsa20poly1305_ZEROBYTES: size_t = 32;
pub const crypto_secretbox_xsalsa20poly1305_BOXZEROBYTES: size_t = 16;
pub const crypto_secretbox_xsalsa20poly1305_MACBYTES: size_t =
    crypto_secretbox_xsalsa20poly1305_ZEROBYTES -
    crypto_secretbox_xsalsa20poly1305_BOXZEROBYTES;


extern {
  // core.h
  pub fn sodium_init() -> c_int;
  
  
  // aead
  // crypto_aead_chacha20poly1305.h
  pub fn crypto_aead_chacha20poly1305_keybytes() -> size_t;
  pub fn crypto_aead_chacha20poly1305_nsecbytes() -> size_t;
  pub fn crypto_aead_chacha20poly1305_npubbytes() -> size_t;
  pub fn crypto_aead_chacha20poly1305_abytes() -> size_t;
  pub fn crypto_aead_chacha20poly1305_encrypt(c: *mut u8,
                                              clen: *mut c_ulonglong,
                                              m: *const u8,
                                              mlen: c_ulonglong,
                                              ad: *const u8,
                                              adlen: c_ulonglong,
                                              nsec: *const u8,
                                              npub: *const u8,
                                              k: *const u8) -> c_int;
  pub fn crypto_aead_chacha20poly1305_decrypt(m: *mut u8,
                                              mlen: *mut c_ulonglong,
                                              nsec: *mut u8,
                                              c: *const u8,
                                              clen: c_ulonglong,
                                              ad: *const u8,
                                              adlen: c_ulonglong,
                                              npub: *const u8,
                                              k: *const u8) -> c_int;


  // auth
  pub fn crypto_auth_bytes() -> size_t;
  pub fn crypto_auth_keybytes() -> size_t;
  pub fn crypto_auth_primitive() -> *const c_char;

  pub fn crypto_auth_hmacsha256(a: *mut u8,
                                m: *const u8,
                                mlen: c_ulonglong,
                                k: *const u8) -> c_int;
  pub fn crypto_auth_hmacsha256_verify(a: *const u8,
                                       m: *const u8,
                                       mlen: c_ulonglong,
                                       k: *const u8) -> c_int;
  pub fn crypto_auth_hmacsha256_bytes() -> size_t;
  pub fn crypto_auth_hmacsha256_keybytes() -> size_t;

  pub fn crypto_auth_hmacsha512(a: *mut u8,
                                m: *const u8,
                                mlen: c_ulonglong,
                                k: *const u8) -> c_int;
  pub fn crypto_auth_hmacsha512_verify(a: *const u8,
                                       m: *const u8,
                                       mlen: c_ulonglong,
                                       k: *const u8) -> c_int;
  pub fn crypto_auth_hmacsha512_bytes() -> size_t;
  pub fn crypto_auth_hmacsha512_keybytes() -> size_t;

  pub fn crypto_auth_hmacsha512256(a: *mut u8,
                                   m: *const u8,
                                   mlen: c_ulonglong,
                                   k: *const u8) -> c_int;
  pub fn crypto_auth_hmacsha512256_verify(a: *const u8,
                                          m: *const u8,
                                          mlen: c_ulonglong,
                                          k: *const u8) -> c_int;
  pub fn crypto_auth_hmacsha512256_bytes() -> size_t;
  pub fn crypto_auth_hmacsha512256_keybytes() -> size_t;


  // onetimeauth
  pub fn crypto_onetimeauth_bytes() -> size_t;
  pub fn crypto_onetimeauth_keybytes() -> size_t;
  pub fn crypto_onetimeauth_primitive() -> *const c_char;

  pub fn crypto_onetimeauth_poly1305(a: *mut u8,
                                     m: *const u8,
                                     mlen: c_ulonglong,
                                     k: *const u8) -> c_int;
  pub fn crypto_onetimeauth_poly1305_verify(a: *const u8,
                                            m: *const u8,
                                            mlen: c_ulonglong,
                                            k: *const u8) -> c_int;
  pub fn crypto_onetimeauth_poly1305_bytes() -> size_t;
  pub fn crypto_onetimeauth_poly1305_keybytes() -> size_t;


  // stream
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


  // hash
  pub fn crypto_hash_bytes() -> size_t;
  pub fn crypto_hash(h: *mut u8,
                     m: *const u8,
                     mlen: c_ulonglong) -> c_int;
  pub fn crypto_hash_primitive() -> *const c_char;
  
  pub fn crypto_hash_sha256(h: *mut u8,
                            m: *const u8,
                            mlen: c_ulonglong) -> c_int;
  pub fn crypto_hash_sha256_bytes() -> size_t;

  pub fn crypto_hash_sha512(h: *mut u8,
                            m: *const u8,
                            mlen: c_ulonglong) -> c_int;
  pub fn crypto_hash_sha512_bytes() -> size_t;


  // scalarmult
  pub fn crypto_scalarmult_curve25519(q: *mut u8,
                                      n: *const u8,
                                      p: *const u8) -> c_int;
  pub fn crypto_scalarmult_curve25519_base(q: *mut u8,
                                           n: *const u8) -> c_int;
  pub fn crypto_scalarmult_curve25519_bytes() -> size_t;
  pub fn crypto_scalarmult_curve25519_scalarbytes() -> size_t;


  // box
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
  pub fn crypto_box_curve25519xsalsa20poly1305_seedbytes() -> size_t;
  pub fn crypto_box_curve25519xsalsa20poly1305_publickeybytes() -> size_t;
  pub fn crypto_box_curve25519xsalsa20poly1305_secretkeybytes() -> size_t;
  pub fn crypto_box_curve25519xsalsa20poly1305_beforenmbytes() -> size_t;
  pub fn crypto_box_curve25519xsalsa20poly1305_noncebytes() -> size_t;
  pub fn crypto_box_curve25519xsalsa20poly1305_zerobytes() -> size_t;
  pub fn crypto_box_curve25519xsalsa20poly1305_boxzerobytes() -> size_t;
  pub fn crypto_box_curve25519xsalsa20poly1305_macbytes() -> size_t;


  // sign
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
  pub fn crypto_sign_ed25519_detached(sig: *mut u8,
                                      siglen: *mut c_ulonglong,
                                      m: *const u8,
                                      mlen: c_ulonglong,
                                      sk: *const u8) -> c_int;
  pub fn crypto_sign_ed25519_verify_detached(sig: *const u8,
                                             m: *const u8,
                                             mlen: c_ulonglong,
                                             pk: *const u8) -> c_int;
  pub fn crypto_sign_ed25519_bytes() -> size_t;
  pub fn crypto_sign_ed25519_seedbytes() -> size_t;
  pub fn crypto_sign_ed25519_publickeybytes() -> size_t;
  pub fn crypto_sign_ed25519_secretkeybytes() -> size_t;

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
  pub fn crypto_sign_edwards25519sha512batch_bytes() -> size_t;
  pub fn crypto_sign_edwards25519sha512batch_publickeybytes() -> size_t;
  pub fn crypto_sign_edwards25519sha512batch_secretkeybytes() -> size_t;
                     

  // shorthash
  pub fn crypto_shorthash_siphash24(h: *mut u8,
                                    m: *const u8,
                                    mlen: c_ulonglong,
                                    k: *const u8) -> c_int;
  pub fn crypto_shorthash_siphash24_bytes() -> size_t;
  pub fn crypto_shorthash_siphash24_keybytes() -> size_t;


  // verify
  pub fn crypto_verify_16(x: *const u8, y: *const u8) -> c_int;
  pub fn crypto_verify_32(x: *const u8, y: *const u8) -> c_int;


  // secretbox
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
  pub fn crypto_secretbox_xsalsa20poly1305_keybytes() -> size_t;
  pub fn crypto_secretbox_xsalsa20poly1305_noncebytes() -> size_t;
  pub fn crypto_secretbox_xsalsa20poly1305_zerobytes() -> size_t;
  pub fn crypto_secretbox_xsalsa20poly1305_boxzerobytes() -> size_t;
  pub fn crypto_secretbox_xsalsa20poly1305_macbytes() -> size_t;


  // randombytes.h
  pub fn randombytes_buf(buf: *mut u8,
                         size: size_t);
}


// aead
#[test]
fn test_crypto_aead_chacha20poly1305_keybytes() {
    assert!(unsafe { crypto_aead_chacha20poly1305_keybytes() } == crypto_aead_chacha20poly1305_KEYBYTES)
}
#[test]
fn test_crypto_aead_chacha20poly1305_nsecbytes() {
    assert!(unsafe { crypto_aead_chacha20poly1305_nsecbytes() } == crypto_aead_chacha20poly1305_NSECBYTES)
}
#[test]
fn test_crypto_aead_chacha20poly1305_npubbytes() {
    assert!(unsafe { crypto_aead_chacha20poly1305_npubbytes() } == crypto_aead_chacha20poly1305_NPUBBYTES)
}
#[test]
fn test_crypto_aead_chacha20poly1305_abytes() {
    assert!(unsafe { crypto_aead_chacha20poly1305_abytes() } == crypto_aead_chacha20poly1305_ABYTES)
}


// auth
#[test]
fn test_crypto_auth_bytes() {
    assert!(unsafe { crypto_auth_bytes() } == crypto_auth_BYTES)
}
#[test]
fn test_crypto_auth_keybytes() {
    assert!(unsafe { crypto_auth_keybytes() } == crypto_auth_KEYBYTES)
}
#[test]
fn test_crypto_auth_primitive() {
    unsafe {
         let s = crypto_auth_primitive();
         let s = std::ffi::c_str_to_bytes(&s);
         assert!(s == crypto_auth_PRIMITIVE.as_bytes());
    }
}

#[test]
fn test_crypto_auth_hmacsha256_bytes() {
    assert!(unsafe { crypto_auth_hmacsha256_bytes() } == crypto_auth_hmacsha256_BYTES)
}
#[test]
fn test_crypto_auth_hmacsha256_keybytes() {
    assert!(unsafe { crypto_auth_hmacsha256_keybytes() } == crypto_auth_hmacsha256_KEYBYTES)
}

#[test]
fn test_crypto_auth_hmacsha512_bytes() {
    assert!(unsafe { crypto_auth_hmacsha512_bytes() } == crypto_auth_hmacsha512_BYTES)
}
#[test]
fn test_crypto_auth_hmacsha512_keybytes() {
    assert!(unsafe { crypto_auth_hmacsha512_keybytes() } == crypto_auth_hmacsha512_KEYBYTES)
}

#[test]
fn test_crypto_auth_hmacsha512256_bytes() {
    assert!(unsafe { crypto_auth_hmacsha512256_bytes() } == crypto_auth_hmacsha512256_BYTES)
}
#[test]
fn test_crypto_auth_hmacsha512256_keybytes() {
    assert!(unsafe { crypto_auth_hmacsha512256_keybytes() } == crypto_auth_hmacsha512256_KEYBYTES)
}


// onetimeauth
#[test]
fn test_crypto_onetimeauth_bytes() {
    assert!(unsafe { crypto_onetimeauth_bytes() } == crypto_onetimeauth_BYTES)
}
#[test]
fn test_crypto_onetimeauth_keybytes() {
    assert!(unsafe { crypto_onetimeauth_keybytes() } == crypto_onetimeauth_KEYBYTES)
}
#[test]
fn test_crypto_onetimeauth_primitive() {
    unsafe {
         let s = crypto_onetimeauth_primitive();
         let s = std::ffi::c_str_to_bytes(&s);
         assert!(s == crypto_onetimeauth_PRIMITIVE.as_bytes());
    }
}
#[test]
fn test_crypto_onetimeauth_poly1305_bytes() {
    assert!(unsafe { crypto_onetimeauth_poly1305_bytes() } == crypto_onetimeauth_poly1305_BYTES)
}
#[test]
fn test_crypto_onetimeauth_poly1305_keybytes() {
    assert!(unsafe { crypto_onetimeauth_poly1305_keybytes() } == crypto_onetimeauth_poly1305_KEYBYTES)
}


// hash
#[test]
fn test_crypto_hash_bytes() {
    assert!(unsafe { crypto_hash_bytes() } == crypto_hash_BYTES)
}
#[test]
fn test_crypto_hash_primitive() {
    unsafe {
         let s = crypto_hash_primitive();
         let s = std::ffi::c_str_to_bytes(&s);
         assert!(s == crypto_hash_PRIMITIVE.as_bytes());
    }
}

#[test]
fn test_crypto_hash_sha256_bytes() {
    assert!(unsafe { crypto_hash_sha256_bytes() } == crypto_hash_sha256_BYTES)
}

#[test]
fn test_crypto_hash_sha512_bytes() {
    assert!(unsafe { crypto_hash_sha512_bytes() } == crypto_hash_sha512_BYTES)
}


// stream
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
    unsafe {
         let s = crypto_stream_primitive();
         let s = std::ffi::c_str_to_bytes(&s);
         assert!(s == crypto_stream_PRIMITIVE.as_bytes());
    }
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


// box
#[test]
fn test_crypto_box_curve25519xsalsa20poly1305_seedbytes() {
    assert!(unsafe { crypto_box_curve25519xsalsa20poly1305_seedbytes() } == crypto_box_curve25519xsalsa20poly1305_SEEDBYTES)
}
#[test]
fn test_crypto_box_curve25519xsalsa20poly1305_publickeybytes() {
    assert!(unsafe { crypto_box_curve25519xsalsa20poly1305_publickeybytes() } == crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES)
}
#[test]
fn test_crypto_box_curve25519xsalsa20poly1305_secretkeybytes() {
    assert!(unsafe { crypto_box_curve25519xsalsa20poly1305_secretkeybytes() } == crypto_box_curve25519xsalsa20poly1305_SECRETKEYBYTES)
}
#[test]
fn test_crypto_box_curve25519xsalsa20poly1305_beforenmbytes() {
    assert!(unsafe { crypto_box_curve25519xsalsa20poly1305_beforenmbytes() } == crypto_box_curve25519xsalsa20poly1305_BEFORENMBYTES)
}
#[test]
fn test_crypto_box_curve25519xsalsa20poly1305_noncebytes() {
    assert!(unsafe { crypto_box_curve25519xsalsa20poly1305_noncebytes() } == crypto_box_curve25519xsalsa20poly1305_NONCEBYTES)
}
#[test]
fn test_crypto_box_curve25519xsalsa20poly1305_zerobytes() {
    assert!(unsafe { crypto_box_curve25519xsalsa20poly1305_zerobytes() } == crypto_box_curve25519xsalsa20poly1305_ZEROBYTES)
}
#[test]
fn test_crypto_box_curve25519xsalsa20poly1305_boxzerobytes() {
    assert!(unsafe { crypto_box_curve25519xsalsa20poly1305_boxzerobytes() } == crypto_box_curve25519xsalsa20poly1305_BOXZEROBYTES)
}
#[test]
fn test_crypto_box_curve25519xsalsa20poly1305_macbytes() {
    assert!(unsafe { crypto_box_curve25519xsalsa20poly1305_macbytes() } == crypto_box_curve25519xsalsa20poly1305_MACBYTES)
}


// scalarmult
#[test]
fn test_crypto_scalarmult_curve25519_bytes() {
    assert!(unsafe { crypto_scalarmult_curve25519_bytes() } == crypto_scalarmult_curve25519_BYTES)
}
#[test]
fn test_crypto_scalarmult_curve25519_scalarbytes() {
    assert!(unsafe { crypto_scalarmult_curve25519_scalarbytes() } == crypto_scalarmult_curve25519_SCALARBYTES)
}


// sign
#[test]
fn test_crypto_sign_ed25519_bytes() {
    assert!(unsafe { crypto_sign_ed25519_bytes() } == crypto_sign_ed25519_BYTES)
}
#[test]
fn test_crypto_sign_ed25519_seedbytes() {
    assert!(unsafe { crypto_sign_ed25519_seedbytes() } == crypto_sign_ed25519_SEEDBYTES)
}
#[test]
fn test_crypto_sign_ed25519_publickeybytes() {
    assert!(unsafe { crypto_sign_ed25519_publickeybytes() } == crypto_sign_ed25519_PUBLICKEYBYTES)
}
#[test]
fn test_crypto_sign_ed25519_secretkeybytes() {
    assert!(unsafe { crypto_sign_ed25519_secretkeybytes() } == crypto_sign_ed25519_SECRETKEYBYTES)
}

#[test]
fn test_crypto_sign_edwards25519sha512batch_bytes() {
    assert!(unsafe { crypto_sign_edwards25519sha512batch_bytes() } == crypto_sign_edwards25519sha512batch_BYTES)
}
#[test]
fn test_crypto_sign_edwards25519sha512batch_publickeybytes() {
    assert!(unsafe { crypto_sign_edwards25519sha512batch_publickeybytes() } == crypto_sign_edwards25519sha512batch_PUBLICKEYBYTES)
}
#[test]
fn test_crypto_sign_edwards25519sha512batch_secretkeybytes() {
    assert!(unsafe { crypto_sign_edwards25519sha512batch_secretkeybytes() } == crypto_sign_edwards25519sha512batch_SECRETKEYBYTES)
}


// shorthash
#[test]
fn test_crypto_shorthash_siphash24_bytes() {
    assert!(unsafe { crypto_shorthash_siphash24_bytes() } == crypto_shorthash_siphash24_BYTES)
}
#[test]
fn test_crypto_shorthash_siphash24_keybytes() {
    assert!(unsafe { crypto_shorthash_siphash24_keybytes() } == crypto_shorthash_siphash24_KEYBYTES)
}


// secretbox
#[test]
fn test_crypto_secretbox_xsalsa20poly1305_keybytes() {
    assert!(unsafe { crypto_secretbox_xsalsa20poly1305_keybytes() } == crypto_secretbox_xsalsa20poly1305_KEYBYTES)
}
#[test]
fn test_crypto_secretbox_xsalsa20poly1305_noncebytes() {
    assert!(unsafe { crypto_secretbox_xsalsa20poly1305_noncebytes() } == crypto_secretbox_xsalsa20poly1305_NONCEBYTES)
}
#[test]
fn test_crypto_secretbox_xsalsa20poly1305_zerobytes() {
    assert!(unsafe { crypto_secretbox_xsalsa20poly1305_zerobytes() } == crypto_secretbox_xsalsa20poly1305_ZEROBYTES)
}
#[test]
fn test_crypto_secretbox_xsalsa20poly1305_boxzerobytes() {
    assert!(unsafe { crypto_secretbox_xsalsa20poly1305_boxzerobytes() } == crypto_secretbox_xsalsa20poly1305_BOXZEROBYTES)
}
#[test]
fn test_crypto_secretbox_xsalsa20poly1305_macbytes() {
    assert!(unsafe { crypto_secretbox_xsalsa20poly1305_macbytes() } == crypto_secretbox_xsalsa20poly1305_MACBYTES)
}
