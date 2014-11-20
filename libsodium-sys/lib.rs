extern crate libc;
use libc::{c_int, c_ulonglong, size_t};

extern {
  pub fn sodium_init() -> c_int;
  
  pub fn randombytes_buf(buf: *mut u8,
                         size: size_t);

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
