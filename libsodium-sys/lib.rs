#![allow(non_upper_case_globals)]
#![feature(libc, std_misc)]
/* workaround: the rust compiler doesn't recognize
   the feature std_misc yet, still it warns
   about using it */
#![allow(unused_features)]
#![feature(std_misc)]

extern crate libc;
use libc::{c_int, c_ulonglong, c_char, size_t};

// aead
pub const crypto_aead_chacha20poly1305_KEYBYTES: usize = 32;
pub const crypto_aead_chacha20poly1305_NSECBYTES: usize = 0;
pub const crypto_aead_chacha20poly1305_NPUBBYTES: usize = 8;
pub const crypto_aead_chacha20poly1305_ABYTES: usize = 16;

// stream
pub const crypto_stream_KEYBYTES: usize = crypto_stream_xsalsa20_KEYBYTES;
pub const crypto_stream_NONCEBYTES: usize =
    crypto_stream_xsalsa20_NONCEBYTES;
pub const crypto_stream_PRIMITIVE: &'static str = "xsalsa20";

pub const crypto_stream_aes128ctr_KEYBYTES: usize = 16;
pub const crypto_stream_aes128ctr_NONCEBYTES: usize = 16;
pub const crypto_stream_aes128ctr_BEFORENMBYTES: usize = 1408;

pub const crypto_stream_chacha20_KEYBYTES: usize = 32;
pub const crypto_stream_chacha20_NONCEBYTES: usize = 8;

pub const crypto_stream_salsa20_KEYBYTES: usize = 32;
pub const crypto_stream_salsa20_NONCEBYTES: usize = 8;

pub const crypto_stream_salsa2012_KEYBYTES: usize = 32;
pub const crypto_stream_salsa2012_NONCEBYTES: usize = 8;

pub const crypto_stream_salsa208_KEYBYTES: usize = 32;
pub const crypto_stream_salsa208_NONCEBYTES: usize = 8;

pub const crypto_stream_xsalsa20_KEYBYTES: usize = 32;
pub const crypto_stream_xsalsa20_NONCEBYTES: usize = 24;

// auth
pub const crypto_auth_BYTES: usize = crypto_auth_hmacsha512256_BYTES;
pub const crypto_auth_KEYBYTES: usize = crypto_auth_hmacsha512256_KEYBYTES;
pub const crypto_auth_PRIMITIVE: &'static str = "hmacsha512256";

pub const crypto_auth_hmacsha256_BYTES: usize = 32;
pub const crypto_auth_hmacsha256_KEYBYTES: usize = 32;

pub const crypto_auth_hmacsha512_BYTES: usize = 64;
pub const crypto_auth_hmacsha512_KEYBYTES: usize = 32;

pub const crypto_auth_hmacsha512256_BYTES: usize = 32;
pub const crypto_auth_hmacsha512256_KEYBYTES: usize = 32;

// onetimeauth
pub const crypto_onetimeauth_BYTES: usize =
    crypto_onetimeauth_poly1305_BYTES;
pub const crypto_onetimeauth_KEYBYTES: usize =
    crypto_onetimeauth_poly1305_KEYBYTES;
pub const crypto_onetimeauth_PRIMITIVE: &'static str =  "poly1305";

pub const crypto_onetimeauth_poly1305_BYTES: usize = 16;
pub const crypto_onetimeauth_poly1305_KEYBYTES: usize = 32;

// pwhash
// crypto_pwhash_scryptsalsa208sha256.h
pub const crypto_pwhash_scryptsalsa208sha256_SALTBYTES: usize = 32;
pub const crypto_pwhash_scryptsalsa208sha256_STRBYTES: usize = 102;
pub const crypto_pwhash_scryptsalsa208sha256_STRPREFIX: &'static str = "$7$";
pub const crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_INTERACTIVE: usize =
    524288;
pub const crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_INTERACTIVE: usize =
    16777216;
pub const crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_SENSITIVE: usize =
    33554432;
pub const crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_SENSITIVE: usize =
    1073741824;

// hash
pub const crypto_hash_BYTES: usize = crypto_hash_sha512_BYTES;
pub const crypto_hash_PRIMITIVE: &'static str = "sha512";

pub const crypto_hash_sha256_BYTES: usize =  32;

pub const crypto_hash_sha512_BYTES: usize = 64;

// box
pub const crypto_box_curve25519xsalsa20poly1305_SEEDBYTES: usize = 32;
pub const crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES: usize = 32;
pub const crypto_box_curve25519xsalsa20poly1305_SECRETKEYBYTES: usize = 32;
pub const crypto_box_curve25519xsalsa20poly1305_BEFORENMBYTES: usize = 32;
pub const crypto_box_curve25519xsalsa20poly1305_NONCEBYTES: usize = 24;
pub const crypto_box_curve25519xsalsa20poly1305_ZEROBYTES: usize = 32;
pub const crypto_box_curve25519xsalsa20poly1305_BOXZEROBYTES: usize = 16;
pub const crypto_box_curve25519xsalsa20poly1305_MACBYTES: usize =
    crypto_box_curve25519xsalsa20poly1305_ZEROBYTES -
    crypto_box_curve25519xsalsa20poly1305_BOXZEROBYTES;

// scalarmult
pub const crypto_scalarmult_curve25519_BYTES: usize = 32;
pub const crypto_scalarmult_curve25519_SCALARBYTES: usize = 32;

// sign
pub const crypto_sign_ed25519_BYTES: usize = 64;
pub const crypto_sign_ed25519_SEEDBYTES: usize = 32;
pub const crypto_sign_ed25519_PUBLICKEYBYTES: usize = 32;
pub const crypto_sign_ed25519_SECRETKEYBYTES: usize = 64;

pub const crypto_sign_edwards25519sha512batch_BYTES: usize = 64;
pub const crypto_sign_edwards25519sha512batch_PUBLICKEYBYTES: usize = 32;
pub const crypto_sign_edwards25519sha512batch_SECRETKEYBYTES: usize = 64;

// shorthash
pub const crypto_shorthash_siphash24_BYTES: usize = 8;
pub const crypto_shorthash_siphash24_KEYBYTES: usize = 16;

// secretbox
pub const crypto_secretbox_xsalsa20poly1305_KEYBYTES: usize = 32;
pub const crypto_secretbox_xsalsa20poly1305_NONCEBYTES: usize = 24;
pub const crypto_secretbox_xsalsa20poly1305_ZEROBYTES: usize = 32;
pub const crypto_secretbox_xsalsa20poly1305_BOXZEROBYTES: usize = 16;
pub const crypto_secretbox_xsalsa20poly1305_MACBYTES: usize =
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
    pub fn crypto_aead_chacha20poly1305_encrypt(
        c: *mut u8,
        clen: *mut c_ulonglong,
        m: *const u8,
        mlen: c_ulonglong,
        ad: *const u8,
        adlen: c_ulonglong,
        nsec: *const [u8; crypto_aead_chacha20poly1305_NSECBYTES],
        npub: *const [u8; crypto_aead_chacha20poly1305_NPUBBYTES],
        k: *const [u8; crypto_aead_chacha20poly1305_KEYBYTES]) -> c_int;
    pub fn crypto_aead_chacha20poly1305_decrypt(
        m: *mut u8,
        mlen: *mut c_ulonglong,
        nsec: *mut [u8; crypto_aead_chacha20poly1305_NSECBYTES],
        c: *const u8,
        clen: c_ulonglong,
        ad: *const u8,
        adlen: c_ulonglong,
        npub: *const [u8; crypto_aead_chacha20poly1305_NPUBBYTES],
        k: *const [u8; crypto_aead_chacha20poly1305_KEYBYTES]) -> c_int;
    
    // auth
    // crypto_auth.h
    pub fn crypto_auth_bytes() -> size_t;
    pub fn crypto_auth_keybytes() -> size_t;
    pub fn crypto_auth_primitive() -> *const c_char;
    pub fn crypto_auth(a: *mut [u8; crypto_auth_BYTES],
                       m: *const u8,
                       mlen: c_ulonglong,
                       k: *const [u8; crypto_auth_KEYBYTES]) -> c_int;
    pub fn crypto_auth_verify(a: *const [u8; crypto_auth_BYTES],
                              m: *const u8,
                              mlen: c_ulonglong,
                              k: *const [u8; crypto_auth_KEYBYTES]) -> c_int;

    // crypto_auth_hmacsha256.h
    pub fn crypto_auth_hmacsha256_bytes() -> size_t;
    pub fn crypto_auth_hmacsha256_keybytes() -> size_t;
    pub fn crypto_auth_hmacsha256(
        a: *mut [u8; crypto_auth_hmacsha256_BYTES],
        m: *const u8,
        mlen: c_ulonglong,
        k: *const [u8; crypto_auth_hmacsha256_KEYBYTES]) -> c_int;
    pub fn crypto_auth_hmacsha256_verify(
        a: *const [u8; crypto_auth_hmacsha256_BYTES],
        m: *const u8,
        mlen: c_ulonglong,
        k: *const [u8; crypto_auth_hmacsha256_KEYBYTES]) -> c_int;
    
    pub fn crypto_auth_hmacsha512(
        a: *mut [u8; crypto_auth_hmacsha512_BYTES],
        m: *const u8,
        mlen: c_ulonglong,
        k: *const [u8; crypto_auth_hmacsha512_KEYBYTES]) -> c_int;
    pub fn crypto_auth_hmacsha512_verify(
        a: *const [u8; crypto_auth_hmacsha512_BYTES],
        m: *const u8,
        mlen: c_ulonglong,
        k: *const [u8; crypto_auth_hmacsha512_KEYBYTES]) -> c_int;
    pub fn crypto_auth_hmacsha512_bytes() -> size_t;
    pub fn crypto_auth_hmacsha512_keybytes() -> size_t;
    
    pub fn crypto_auth_hmacsha512256(
        a: *mut [u8; crypto_auth_hmacsha512256_BYTES],
        m: *const u8,
        mlen: c_ulonglong,
        k: *const [u8; crypto_auth_hmacsha512256_KEYBYTES]) -> c_int;
    pub fn crypto_auth_hmacsha512256_verify(
        a: *const [u8; crypto_auth_hmacsha512256_BYTES],
        m: *const u8,
        mlen: c_ulonglong,
        k: *const [u8; crypto_auth_hmacsha512256_KEYBYTES]) -> c_int;
    pub fn crypto_auth_hmacsha512256_bytes() -> size_t;
    pub fn crypto_auth_hmacsha512256_keybytes() -> size_t;
    
    // onetimeauth
    pub fn crypto_onetimeauth_bytes() -> size_t;
    pub fn crypto_onetimeauth_keybytes() -> size_t;
    pub fn crypto_onetimeauth_primitive() -> *const c_char;
    
    pub fn crypto_onetimeauth_poly1305(
        a: *mut [u8; crypto_onetimeauth_poly1305_BYTES],
        m: *const u8,
        mlen: c_ulonglong,
        k: *const [u8; crypto_onetimeauth_poly1305_KEYBYTES]) -> c_int;
    pub fn crypto_onetimeauth_poly1305_verify(
        a: *const [u8; crypto_onetimeauth_poly1305_BYTES],
        m: *const u8,
        mlen: c_ulonglong,
        k: *const [u8; crypto_onetimeauth_poly1305_KEYBYTES]) -> c_int;
    pub fn crypto_onetimeauth_poly1305_bytes() -> size_t;
    pub fn crypto_onetimeauth_poly1305_keybytes() -> size_t;
    
    // pwhash
    // crypto_pwhash_scryptsalsa208sha256.h
    pub fn crypto_pwhash_scryptsalsa208sha256_saltbytes() -> size_t;
    pub fn crypto_pwhash_scryptsalsa208sha256_strbytes() -> size_t;
    pub fn crypto_pwhash_scryptsalsa208sha256_strprefix() -> *const c_char;
    pub fn crypto_pwhash_scryptsalsa208sha256_opslimit_interactive() ->
        size_t;
    pub fn crypto_pwhash_scryptsalsa208sha256_memlimit_interactive() ->
        size_t;
    pub fn crypto_pwhash_scryptsalsa208sha256_opslimit_sensitive() -> size_t;
    pub fn crypto_pwhash_scryptsalsa208sha256_memlimit_sensitive() -> size_t;
    pub fn crypto_pwhash_scryptsalsa208sha256(
        out: *mut u8,
        outlen: c_ulonglong,
        passwd: *const c_char,
        passwdlen: c_ulonglong,
        salt: *const [u8; crypto_pwhash_scryptsalsa208sha256_SALTBYTES],
        opslimit: c_ulonglong,
        memlimit: size_t) -> c_int;
    pub fn crypto_pwhash_scryptsalsa208sha256_str(
        out: *mut [c_char; crypto_pwhash_scryptsalsa208sha256_STRBYTES],
        passwd: *const c_char,
        passwdlen: c_ulonglong,
        opslimit: c_ulonglong,
        memlimit: size_t) -> c_int;
    pub fn crypto_pwhash_scryptsalsa208sha256_str_verify(
        str_: *const [c_char; crypto_pwhash_scryptsalsa208sha256_STRBYTES],
        passwd: *const c_char,
        passwdlen: c_ulonglong) -> c_int;
    pub fn crypto_pwhash_scryptsalsa208sha256_ll(
        passwd: *const u8,
        passwdlen: size_t,
        salt: *const u8,
        saltlen: size_t,
        N: u64,
        r: u32,
        p: u32,
        buf: *mut u8,
        buflen: size_t) -> c_int;
    
    // stream
    pub fn crypto_stream_keybytes() -> size_t;
    pub fn crypto_stream_noncebytes() -> size_t;
    pub fn crypto_stream_primitive() -> *const c_char;
    
    pub fn crypto_stream_aes128ctr(
        c: *mut u8,
        clen: c_ulonglong,
        n: *const [u8; crypto_stream_aes128ctr_NONCEBYTES],
        k: *const [u8; crypto_stream_aes128ctr_KEYBYTES]) -> c_int;
    pub fn crypto_stream_aes128ctr_xor(
        c: *mut u8,
        m: *const u8,
        mlen: c_ulonglong,
        n: *const [u8; crypto_stream_aes128ctr_NONCEBYTES],
        k: *const [u8; crypto_stream_aes128ctr_KEYBYTES]) -> c_int;
    pub fn crypto_stream_aes128ctr_keybytes() -> size_t;
    pub fn crypto_stream_aes128ctr_noncebytes() -> size_t;
    pub fn crypto_stream_aes128ctr_beforenmbytes() -> size_t;
    
    pub fn crypto_stream_chacha20_keybytes() -> size_t;
    pub fn crypto_stream_chacha20_noncebytes() -> size_t;
    
    pub fn crypto_stream_salsa20(
        c: *mut u8,
        clen: c_ulonglong,
        n: *const [u8; crypto_stream_salsa20_NONCEBYTES],
        k: *const [u8; crypto_stream_salsa20_KEYBYTES]) -> c_int;
    pub fn crypto_stream_salsa20_xor(
        c: *mut u8,
        m: *const u8,
        mlen: c_ulonglong,
        n: *const [u8; crypto_stream_salsa20_NONCEBYTES],
        k: *const [u8; crypto_stream_salsa20_KEYBYTES]) -> c_int;
    pub fn crypto_stream_salsa20_keybytes() -> size_t;
    pub fn crypto_stream_salsa20_noncebytes() -> size_t;
    
    pub fn crypto_stream_salsa208(
        c: *mut u8,
        clen: c_ulonglong,
        n: *const [u8; crypto_stream_salsa208_NONCEBYTES],
        k: *const [u8; crypto_stream_salsa208_KEYBYTES]) -> c_int;
    pub fn crypto_stream_salsa208_xor(
        c: *mut u8,
        m: *const u8,
        mlen: c_ulonglong,
        n: *const [u8; crypto_stream_salsa208_NONCEBYTES],
        k: *const [u8; crypto_stream_salsa208_KEYBYTES]) -> c_int;
    pub fn crypto_stream_salsa208_keybytes() -> size_t;
    pub fn crypto_stream_salsa208_noncebytes() -> size_t;
    
    pub fn crypto_stream_salsa2012(
        c: *mut u8,
        clen: c_ulonglong,
        n: *const [u8; crypto_stream_salsa2012_NONCEBYTES],
        k: *const [u8; crypto_stream_salsa2012_KEYBYTES]) -> c_int;
    pub fn crypto_stream_salsa2012_xor(
        c: *mut u8,
        m: *const u8,
        mlen: c_ulonglong,
        n: *const [u8; crypto_stream_salsa2012_NONCEBYTES],
        k: *const [u8; crypto_stream_salsa2012_KEYBYTES]) -> c_int;
    pub fn crypto_stream_salsa2012_keybytes() -> size_t;
    pub fn crypto_stream_salsa2012_noncebytes() -> size_t;
    
    pub fn crypto_stream_xsalsa20(
        c: *mut u8,
        clen: c_ulonglong,
        n: *const [u8; crypto_stream_xsalsa20_NONCEBYTES],
        k: *const [u8; crypto_stream_xsalsa20_KEYBYTES]) -> c_int;
    pub fn crypto_stream_xsalsa20_xor(
        c: *mut u8,
        m: *const u8,
        mlen: c_ulonglong,
        n: *const [u8; crypto_stream_xsalsa20_NONCEBYTES],
        k: *const [u8; crypto_stream_xsalsa20_KEYBYTES]) -> c_int;
    pub fn crypto_stream_xsalsa20_keybytes() -> size_t;
    pub fn crypto_stream_xsalsa20_noncebytes() -> size_t;
    
    // hash
    pub fn crypto_hash_bytes() -> size_t;
    pub fn crypto_hash(h: *mut [u8; crypto_hash_BYTES],
                       m: *const u8,
                       mlen: c_ulonglong) -> c_int;
    pub fn crypto_hash_primitive() -> *const c_char;
    
    pub fn crypto_hash_sha256(h: *mut [u8; crypto_hash_sha256_BYTES],
                              m: *const u8,
                              mlen: c_ulonglong) -> c_int;
    pub fn crypto_hash_sha256_bytes() -> size_t;
    
    pub fn crypto_hash_sha512(h: *mut [u8; crypto_hash_sha512_BYTES],
                              m: *const u8,
                              mlen: c_ulonglong) -> c_int;
    pub fn crypto_hash_sha512_bytes() -> size_t;
    
    // scalarmult
    pub fn crypto_scalarmult_curve25519(
        q: *mut [u8; crypto_scalarmult_curve25519_BYTES],
        n: *const [u8; crypto_scalarmult_curve25519_SCALARBYTES],
        p: *const [u8; crypto_scalarmult_curve25519_BYTES]) -> c_int;
    pub fn crypto_scalarmult_curve25519_base(
        q: *mut [u8; crypto_scalarmult_curve25519_BYTES],
        n: *const [u8; crypto_scalarmult_curve25519_SCALARBYTES]) -> c_int;
    pub fn crypto_scalarmult_curve25519_bytes() -> size_t;
    pub fn crypto_scalarmult_curve25519_scalarbytes() -> size_t;
    
    // box
    pub fn crypto_box_curve25519xsalsa20poly1305_keypair(
        pk: *mut [u8; crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES],
        sk: *mut [u8; crypto_box_curve25519xsalsa20poly1305_SECRETKEYBYTES])
        -> c_int;
    pub fn crypto_box_curve25519xsalsa20poly1305(
        c: *mut u8,
        m: *const u8,
        mlen: c_ulonglong,
        n: *const [u8; crypto_box_curve25519xsalsa20poly1305_NONCEBYTES],
        pk: *const [u8; crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES],
        sk: *const [u8; crypto_box_curve25519xsalsa20poly1305_SECRETKEYBYTES])
        -> c_int;
    pub fn crypto_box_curve25519xsalsa20poly1305_open(
        m: *mut u8,
        c: *const u8,
        clen: c_ulonglong,
        n: *const [u8; crypto_box_curve25519xsalsa20poly1305_NONCEBYTES],
        pk: *const [u8; crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES],
        sk: *const [u8; crypto_box_curve25519xsalsa20poly1305_SECRETKEYBYTES])
        -> c_int;
    pub fn crypto_box_curve25519xsalsa20poly1305_beforenm(
        k: *mut [u8; crypto_box_curve25519xsalsa20poly1305_BEFORENMBYTES],
        pk: *const [u8; crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES],
        sk: *const [u8; crypto_box_curve25519xsalsa20poly1305_SECRETKEYBYTES])
        -> c_int;
    pub fn crypto_box_curve25519xsalsa20poly1305_afternm(
        c: *mut u8,
        m: *const u8,
        mlen: c_ulonglong,
        n: *const [u8; crypto_box_curve25519xsalsa20poly1305_NONCEBYTES],
        k: *const [u8; crypto_box_curve25519xsalsa20poly1305_BEFORENMBYTES])
        -> c_int;
    pub fn crypto_box_curve25519xsalsa20poly1305_open_afternm(
        m: *mut u8,
        c: *const u8,
        clen: c_ulonglong,
        n: *const [u8; crypto_box_curve25519xsalsa20poly1305_NONCEBYTES],
        k: *const [u8; crypto_box_curve25519xsalsa20poly1305_BEFORENMBYTES])
        -> c_int;
    pub fn crypto_box_curve25519xsalsa20poly1305_seedbytes() -> size_t;
    pub fn crypto_box_curve25519xsalsa20poly1305_publickeybytes() -> size_t;
    pub fn crypto_box_curve25519xsalsa20poly1305_secretkeybytes() -> size_t;
    pub fn crypto_box_curve25519xsalsa20poly1305_beforenmbytes() -> size_t;
    pub fn crypto_box_curve25519xsalsa20poly1305_noncebytes() -> size_t;
    pub fn crypto_box_curve25519xsalsa20poly1305_zerobytes() -> size_t;
    pub fn crypto_box_curve25519xsalsa20poly1305_boxzerobytes() -> size_t;
    pub fn crypto_box_curve25519xsalsa20poly1305_macbytes() -> size_t;
    
    // sign
    pub fn crypto_sign_ed25519_keypair(
        pk: *mut [u8; crypto_sign_ed25519_PUBLICKEYBYTES],
        sk: *mut [u8; crypto_sign_ed25519_SECRETKEYBYTES]) -> c_int;
    pub fn crypto_sign_ed25519_seed_keypair(
        pk: *mut [u8; crypto_sign_ed25519_PUBLICKEYBYTES],
        sk: *mut [u8; crypto_sign_ed25519_SECRETKEYBYTES],
        seed: *const [u8; crypto_sign_ed25519_SEEDBYTES]) -> c_int;
    pub fn crypto_sign_ed25519(
        sm: *mut u8,
        smlen: *mut c_ulonglong,
        m: *const u8,
        mlen: c_ulonglong,
        sk: *const [u8; crypto_sign_ed25519_SECRETKEYBYTES]) -> c_int;
    pub fn crypto_sign_ed25519_open(
        m: *mut u8,
        mlen: *mut c_ulonglong,
        sm: *const u8,
        smlen: c_ulonglong,
        pk: *const [u8; crypto_sign_ed25519_PUBLICKEYBYTES]) -> c_int;
    pub fn crypto_sign_ed25519_detached(
        sig: *mut [u8; crypto_sign_ed25519_BYTES],
        siglen: *mut c_ulonglong,
        m: *const u8,
        mlen: c_ulonglong,
        sk: *const [u8; crypto_sign_ed25519_SECRETKEYBYTES]) -> c_int;
    pub fn crypto_sign_ed25519_verify_detached(
        sig: *const u8,
        m: *const u8,
        mlen: c_ulonglong,
        pk: *const [u8; crypto_sign_ed25519_PUBLICKEYBYTES]) -> c_int;
    pub fn crypto_sign_ed25519_bytes() -> size_t;
    pub fn crypto_sign_ed25519_seedbytes() -> size_t;
    pub fn crypto_sign_ed25519_publickeybytes() -> size_t;
    pub fn crypto_sign_ed25519_secretkeybytes() -> size_t;
    
    pub fn crypto_sign_edwards25519sha512batch_keypair(
        pk: *mut [u8; crypto_sign_edwards25519sha512batch_PUBLICKEYBYTES],
        sk: *mut [u8; crypto_sign_edwards25519sha512batch_SECRETKEYBYTES])
        -> c_int;
    pub fn crypto_sign_edwards25519sha512batch(
        sm: *mut u8,
        smlen: *mut c_ulonglong,
        m: *const u8,
        mlen: c_ulonglong,
        sk: *const [u8; crypto_sign_edwards25519sha512batch_SECRETKEYBYTES])
        -> c_int;
    pub fn crypto_sign_edwards25519sha512batch_open(
        m: *mut u8,
        mlen: *mut c_ulonglong,
        sm: *const u8,
        smlen: c_ulonglong,
        pk: *const [u8; crypto_sign_edwards25519sha512batch_PUBLICKEYBYTES]) ->
        c_int;
    pub fn crypto_sign_edwards25519sha512batch_bytes() -> size_t;
    pub fn crypto_sign_edwards25519sha512batch_publickeybytes() -> size_t;
    pub fn crypto_sign_edwards25519sha512batch_secretkeybytes() -> size_t;
    
    // shorthash
    pub fn crypto_shorthash_siphash24(
        h: *mut [u8; crypto_shorthash_siphash24_BYTES],
        m: *const u8,
        mlen: c_ulonglong,
        k: *const [u8; crypto_shorthash_siphash24_KEYBYTES]) -> c_int;
    pub fn crypto_shorthash_siphash24_bytes() -> size_t;
    pub fn crypto_shorthash_siphash24_keybytes() -> size_t;
    
    // verify
    pub fn crypto_verify_16(x: *const u8, y: *const u8) -> c_int;
    pub fn crypto_verify_32(x: *const u8, y: *const u8) -> c_int;

    // secretbox
    pub fn crypto_secretbox_xsalsa20poly1305(
        c: *mut u8,
        m: *const u8,
        mlen: c_ulonglong,
        n: *const [u8; crypto_secretbox_xsalsa20poly1305_NONCEBYTES],
        k: *const [u8; crypto_secretbox_xsalsa20poly1305_KEYBYTES]) -> c_int;
    pub fn crypto_secretbox_xsalsa20poly1305_open(
        m: *mut u8,
        c: *const u8,
        clen: c_ulonglong,
        n: *const [u8; crypto_secretbox_xsalsa20poly1305_NONCEBYTES],
        k: *const [u8; crypto_secretbox_xsalsa20poly1305_KEYBYTES]) -> c_int;
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
    assert!(unsafe { crypto_aead_chacha20poly1305_keybytes() as usize } ==
            crypto_aead_chacha20poly1305_KEYBYTES)
}
#[test]
fn test_crypto_aead_chacha20poly1305_nsecbytes() {
    assert!(unsafe { crypto_aead_chacha20poly1305_nsecbytes() as usize } ==
            crypto_aead_chacha20poly1305_NSECBYTES)
}
#[test]
fn test_crypto_aead_chacha20poly1305_npubbytes() {
    assert!(unsafe { crypto_aead_chacha20poly1305_npubbytes() as usize } ==
            crypto_aead_chacha20poly1305_NPUBBYTES)
}
#[test]
fn test_crypto_aead_chacha20poly1305_abytes() {
    assert!(unsafe { crypto_aead_chacha20poly1305_abytes() as usize } ==
            crypto_aead_chacha20poly1305_ABYTES)
}

// auth
// crypto_auth.h
#[test]
fn test_crypto_auth_bytes() {
    assert!(unsafe { crypto_auth_bytes() as usize } == crypto_auth_BYTES)
}
#[test]
fn test_crypto_auth_keybytes() {
    assert!(unsafe { crypto_auth_keybytes() as usize } ==
            crypto_auth_KEYBYTES)
}
#[test]
fn test_crypto_auth_primitive() {
    unsafe {
        let s = crypto_auth_primitive();
        let s = std::ffi::c_str_to_bytes(&s);
        assert!(s == crypto_auth_PRIMITIVE.as_bytes());
    }
}

// crypto_auth_hmacsha256.h
#[test]
fn test_crypto_auth_hmacsha256_bytes() {
    assert!(unsafe { crypto_auth_hmacsha256_bytes() as usize } ==
            crypto_auth_hmacsha256_BYTES)
}
#[test]
fn test_crypto_auth_hmacsha256_keybytes() {
    assert!(unsafe { crypto_auth_hmacsha256_keybytes() as usize } ==
            crypto_auth_hmacsha256_KEYBYTES)
}

#[test]
fn test_crypto_auth_hmacsha512_bytes() {
    assert!(unsafe { crypto_auth_hmacsha512_bytes() as usize } ==
            crypto_auth_hmacsha512_BYTES)
}
#[test]
fn test_crypto_auth_hmacsha512_keybytes() {
    assert!(unsafe { crypto_auth_hmacsha512_keybytes() as usize } ==
            crypto_auth_hmacsha512_KEYBYTES)
}

#[test]
fn test_crypto_auth_hmacsha512256_bytes() {
    assert!(unsafe { crypto_auth_hmacsha512256_bytes() as usize } ==
            crypto_auth_hmacsha512256_BYTES)
}
#[test]
fn test_crypto_auth_hmacsha512256_keybytes() {
    assert!(unsafe { crypto_auth_hmacsha512256_keybytes() as usize } ==
            crypto_auth_hmacsha512256_KEYBYTES)
}

// onetimeauth
#[test]
fn test_crypto_onetimeauth_bytes() {
    assert!(unsafe { crypto_onetimeauth_bytes() as usize } ==
            crypto_onetimeauth_BYTES)
}
#[test]
fn test_crypto_onetimeauth_keybytes() {
    assert!(unsafe { crypto_onetimeauth_keybytes() as usize } ==
            crypto_onetimeauth_KEYBYTES)
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
    assert!(unsafe { crypto_onetimeauth_poly1305_bytes() as usize } ==
            crypto_onetimeauth_poly1305_BYTES)
}
#[test]
fn test_crypto_onetimeauth_poly1305_keybytes() {
    assert!(unsafe { crypto_onetimeauth_poly1305_keybytes() as usize } ==
            crypto_onetimeauth_poly1305_KEYBYTES)
}

//pwhash
#[test]
fn test_crypto_pwhash_scryptsalsa208sha256_saltbytes() {
    assert!(unsafe {
        crypto_pwhash_scryptsalsa208sha256_saltbytes() as usize
    } == crypto_pwhash_scryptsalsa208sha256_SALTBYTES)
}
#[test]
fn test_crypto_pwhash_scryptsalsa208sha256_strbytes() {
    assert!(unsafe {
        crypto_pwhash_scryptsalsa208sha256_strbytes() as usize
    } == crypto_pwhash_scryptsalsa208sha256_STRBYTES)
}
#[test]
fn test_crypto_pwhash_scryptsalsa208sha256_opslimit_interactive() {
    assert!(unsafe {
        crypto_pwhash_scryptsalsa208sha256_opslimit_interactive() as usize
    } == crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_INTERACTIVE)
}
#[test]
fn test_crypto_pwhash_scryptsalsa208sha256_memlimit_interactive() {
    assert!(unsafe {
        crypto_pwhash_scryptsalsa208sha256_memlimit_interactive() as usize
    } == crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_INTERACTIVE)
}
#[test]
fn test_crypto_pwhash_scryptsalsa208sha256_opslimit_sensitive() {
    assert!(unsafe {
        crypto_pwhash_scryptsalsa208sha256_opslimit_sensitive() as usize
    } == crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_SENSITIVE)
}
#[test]
fn test_crypto_pwhash_scryptsalsa208sha256_memlimit_sensitive() {
    assert!(unsafe {
        crypto_pwhash_scryptsalsa208sha256_memlimit_sensitive() as usize
    } == crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_SENSITIVE)
}
#[test]
fn test_crypto_pwhash_scryptsalsa208sha256_strprefix() {
    unsafe {
         let s = crypto_pwhash_scryptsalsa208sha256_strprefix();
         let s = std::ffi::c_str_to_bytes(&s);
        assert!(s ==
                crypto_pwhash_scryptsalsa208sha256_STRPREFIX.as_bytes());
    }
}
#[test]
fn test_crypto_pwhash_scryptsalsa208sha256_str() {
    let password = "Correct Horse Battery Staple";
    let mut hashed_password =
        [0 as c_char; crypto_pwhash_scryptsalsa208sha256_STRBYTES];
    let ret_hash = unsafe {
        crypto_pwhash_scryptsalsa208sha256_str(
            &mut hashed_password,
            password.as_ptr() as *const c_char,
            password.len() as c_ulonglong,
            crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_INTERACTIVE
                as c_ulonglong,
            crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_INTERACTIVE
                as size_t)
    };
    assert!(ret_hash == 0);
    let ret_verify = unsafe {
        crypto_pwhash_scryptsalsa208sha256_str_verify(
            &hashed_password,
            password.as_ptr() as *const c_char,
            password.len() as c_ulonglong)
    };
    assert!(ret_verify == 0);
}
#[test]
fn test_crypto_pwhash_scryptsalsa208sha256_ll_1() {
    // See https://www.tarsnap.com/scrypt/scrypt.pdf Page 16
    let password = "";
    let salt = "";
    let n = 16;
    let r = 1;
    let p = 1;
    let mut buf = [0u8; 64];
    let expected = [0x77, 0xd6, 0x57, 0x62, 0x38, 0x65, 0x7b, 0x20,
                    0x3b, 0x19, 0xca, 0x42, 0xc1, 0x8a, 0x04, 0x97,
                    0xf1, 0x6b, 0x48, 0x44, 0xe3, 0x07, 0x4a, 0xe8,
                    0xdf, 0xdf, 0xfa, 0x3f, 0xed, 0xe2, 0x14, 0x42,
                    0xfc, 0xd0, 0x06, 0x9d, 0xed, 0x09, 0x48, 0xf8,
                    0x32, 0x6a, 0x75, 0x3a, 0x0f, 0xc8, 0x1f, 0x17,
                    0xe8, 0xd3, 0xe0, 0xfb, 0x2e, 0x0d, 0x36, 0x28,
                    0xcf, 0x35, 0xe2, 0x0c, 0x38, 0xd1, 0x89, 0x06];
    let ret = unsafe {
        crypto_pwhash_scryptsalsa208sha256_ll(password.as_ptr(),
                                              password.len() as size_t,
                                              salt.as_ptr(),
                                              salt.len() as size_t,
                                              n,
                                              r,
                                              p,
                                              buf.as_mut_ptr(),
                                              buf.len() as size_t)
    };
    assert!(ret == 0);
    assert!(buf[0..] == expected[0..]);
}
#[test]
fn test_crypto_pwhash_scryptsalsa208sha256_ll_2() {
    // See https://www.tarsnap.com/scrypt/scrypt.pdf Page 16
    let password = "password";
    let salt = "NaCl";
    let n = 1024;
    let r = 8;
    let p = 16;
    let mut buf = [0u8; 64];
    let expected = [0xfd, 0xba, 0xbe, 0x1c, 0x9d, 0x34, 0x72, 0x00,
                    0x78, 0x56, 0xe7, 0x19, 0x0d, 0x01, 0xe9, 0xfe,
                    0x7c, 0x6a, 0xd7, 0xcb, 0xc8, 0x23, 0x78, 0x30,
                    0xe7, 0x73, 0x76, 0x63, 0x4b, 0x37, 0x31, 0x62,
                    0x2e, 0xaf, 0x30, 0xd9, 0x2e, 0x22, 0xa3, 0x88,
                    0x6f, 0xf1, 0x09, 0x27, 0x9d, 0x98, 0x30, 0xda,
                    0xc7, 0x27, 0xaf, 0xb9, 0x4a, 0x83, 0xee, 0x6d,
                    0x83, 0x60, 0xcb, 0xdf, 0xa2, 0xcc, 0x06, 0x40];
    let ret = unsafe {
        crypto_pwhash_scryptsalsa208sha256_ll(password.as_ptr(),
                                              password.len() as size_t,
                                              salt.as_ptr(),
                                              salt.len() as size_t,
                                              n,
                                              r,
                                              p,
                                              buf.as_mut_ptr(),
                                              buf.len() as size_t)
    };
    assert!(ret == 0);
    assert!(buf[0..] == expected[0..]);
}
#[test]
fn test_crypto_pwhash_scryptsalsa208sha256_ll_3() {
    // See https://www.tarsnap.com/scrypt/scrypt.pdf Page 16
    let password = "pleaseletmein";
    let salt = "SodiumChloride";
    let n = 16384;
    let r = 8;
    let p = 1;
    let mut buf = [0u8; 64];
    let expected = [0x70, 0x23, 0xbd, 0xcb, 0x3a, 0xfd, 0x73, 0x48,
                    0x46, 0x1c, 0x06, 0xcd, 0x81, 0xfd, 0x38, 0xeb,
                    0xfd, 0xa8, 0xfb, 0xba, 0x90, 0x4f, 0x8e, 0x3e,
                    0xa9, 0xb5, 0x43, 0xf6, 0x54, 0x5d, 0xa1, 0xf2,
                    0xd5, 0x43, 0x29, 0x55, 0x61, 0x3f, 0x0f, 0xcf,
                    0x62, 0xd4, 0x97, 0x05, 0x24, 0x2a, 0x9a, 0xf9,
                    0xe6, 0x1e, 0x85, 0xdc, 0x0d, 0x65, 0x1e, 0x40,
                    0xdf, 0xcf, 0x01, 0x7b, 0x45, 0x57, 0x58, 0x87];
    let ret = unsafe {
        crypto_pwhash_scryptsalsa208sha256_ll(password.as_ptr(),
                                              password.len() as size_t,
                                              salt.as_ptr(),
                                              salt.len() as size_t,
                                              n,
                                              r,
                                              p,
                                              buf.as_mut_ptr(),
                                              buf.len() as size_t)
    };
    assert!(ret == 0);
    assert!(buf[0..] == expected[0..]);
}
#[test]
fn test_crypto_pwhash_scryptsalsa208sha256_ll_4() {
    // See https://www.tarsnap.com/scrypt/scrypt.pdf Page 16
    let password = "pleaseletmein";
    let salt = "SodiumChloride";
    let n = 1048576;
    let r = 8;
    let p = 1;
    let mut buf = [0u8; 64];
    let expected = [0x21, 0x01, 0xcb, 0x9b, 0x6a, 0x51, 0x1a, 0xae,
                    0xad, 0xdb, 0xbe, 0x09, 0xcf, 0x70, 0xf8, 0x81,
                    0xec, 0x56, 0x8d, 0x57, 0x4a, 0x2f, 0xfd, 0x4d,
                    0xab, 0xe5, 0xee, 0x98, 0x20, 0xad, 0xaa, 0x47,
                    0x8e, 0x56, 0xfd, 0x8f, 0x4b, 0xa5, 0xd0, 0x9f,
                    0xfa, 0x1c, 0x6d, 0x92, 0x7c, 0x40, 0xf4, 0xc3,
                    0x37, 0x30, 0x40, 0x49, 0xe8, 0xa9, 0x52, 0xfb,
                    0xcb, 0xf4, 0x5c, 0x6f, 0xa7, 0x7a, 0x41, 0xa4];
    let ret = unsafe {
        crypto_pwhash_scryptsalsa208sha256_ll(password.as_ptr(),
                                              password.len() as size_t,
                                              salt.as_ptr(),
                                              salt.len() as size_t,
                                              n,
                                              r,
                                              p,
                                              buf.as_mut_ptr(),
                                              buf.len() as size_t)
    };
    assert!(ret == 0);
    assert!(buf[0..] == expected[0..]);
}

// hash
#[test]
fn test_crypto_hash_bytes() {
    assert!(unsafe { crypto_hash_bytes() as usize } == crypto_hash_BYTES)
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
    assert!(unsafe { crypto_hash_sha256_bytes() as usize } ==
            crypto_hash_sha256_BYTES)
}

#[test]
fn test_crypto_hash_sha512_bytes() {
    assert!(unsafe { crypto_hash_sha512_bytes() as usize } ==
            crypto_hash_sha512_BYTES)
}

// stream
#[test]
fn test_crypto_stream_keybytes() {
    assert!(unsafe { crypto_stream_keybytes() as usize } ==
            crypto_stream_KEYBYTES)
}
#[test]
fn test_crypto_stream_noncebytes() {
    assert!(unsafe { crypto_stream_noncebytes() as usize } ==
            crypto_stream_NONCEBYTES)
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
    assert!(unsafe { crypto_stream_aes128ctr_keybytes() as usize } ==
            crypto_stream_aes128ctr_KEYBYTES)
}
#[test]
fn test_crypto_stream_aes128ctr_noncebytes() {
    assert!(unsafe { crypto_stream_aes128ctr_noncebytes() as usize } ==
            crypto_stream_aes128ctr_NONCEBYTES)
}
#[test]
fn test_crypto_stream_aes128ctr_beforenmbytes() {
    assert!(unsafe { crypto_stream_aes128ctr_beforenmbytes() as usize } ==
            crypto_stream_aes128ctr_BEFORENMBYTES)
}

#[test]
fn test_crypto_stream_chacha20_keybytes() {
    assert!(unsafe { crypto_stream_chacha20_keybytes() as usize } ==
            crypto_stream_chacha20_KEYBYTES)
}
#[test]
fn test_crypto_stream_chacha20_noncebytes() {
    assert!(unsafe { crypto_stream_chacha20_noncebytes() as usize } ==
            crypto_stream_chacha20_NONCEBYTES)
}

#[test]
fn test_crypto_stream_salsa20_keybytes() {
    assert!(unsafe { crypto_stream_salsa20_keybytes() as usize } ==
            crypto_stream_salsa20_KEYBYTES)
}
#[test]
fn test_crypto_stream_salsa20_noncebytes() {
    assert!(unsafe { crypto_stream_salsa20_noncebytes() as usize } ==
            crypto_stream_salsa20_NONCEBYTES)
}

#[test]
fn test_crypto_stream_salsa208_keybytes() {
    assert!(unsafe { crypto_stream_salsa208_keybytes() as usize } ==
            crypto_stream_salsa208_KEYBYTES)
}
#[test]
fn test_crypto_stream_salsa208_noncebytes() {
    assert!(unsafe { crypto_stream_salsa208_noncebytes() as usize } ==
            crypto_stream_salsa208_NONCEBYTES)
}

#[test]
fn test_crypto_stream_salsa2012_keybytes() {
    assert!(unsafe { crypto_stream_salsa2012_keybytes() as usize } ==
            crypto_stream_salsa2012_KEYBYTES)
}
#[test]
fn test_crypto_stream_salsa2012_noncebytes() {
    assert!(unsafe { crypto_stream_salsa2012_noncebytes() as usize } ==
            crypto_stream_salsa2012_NONCEBYTES)
}

#[test]
fn test_crypto_stream_xsalsa20_keybytes() {
    assert!(unsafe { crypto_stream_xsalsa20_keybytes() as usize } ==
            crypto_stream_xsalsa20_KEYBYTES)
}
#[test]
fn test_crypto_stream_xsalsa20_noncebytes() {
    assert!(unsafe { crypto_stream_xsalsa20_noncebytes() as usize } ==
            crypto_stream_xsalsa20_NONCEBYTES)
}

// box
#[test]
fn test_crypto_box_curve25519xsalsa20poly1305_seedbytes() {
    assert!(unsafe {
        crypto_box_curve25519xsalsa20poly1305_seedbytes() as usize
    } == crypto_box_curve25519xsalsa20poly1305_SEEDBYTES)
}
#[test]
fn test_crypto_box_curve25519xsalsa20poly1305_publickeybytes() {
    assert!(unsafe {
        crypto_box_curve25519xsalsa20poly1305_publickeybytes() as usize
    } == crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES)
}
#[test]
fn test_crypto_box_curve25519xsalsa20poly1305_secretkeybytes() {
    assert!(unsafe {
        crypto_box_curve25519xsalsa20poly1305_secretkeybytes() as usize
    } == crypto_box_curve25519xsalsa20poly1305_SECRETKEYBYTES)
}
#[test]
fn test_crypto_box_curve25519xsalsa20poly1305_beforenmbytes() {
    assert!(unsafe {
        crypto_box_curve25519xsalsa20poly1305_beforenmbytes() as usize
    } == crypto_box_curve25519xsalsa20poly1305_BEFORENMBYTES)
}
#[test]
fn test_crypto_box_curve25519xsalsa20poly1305_noncebytes() {
    assert!(unsafe {
        crypto_box_curve25519xsalsa20poly1305_noncebytes() as usize
    } == crypto_box_curve25519xsalsa20poly1305_NONCEBYTES)
}
#[test]
fn test_crypto_box_curve25519xsalsa20poly1305_zerobytes() {
    assert!(unsafe {
        crypto_box_curve25519xsalsa20poly1305_zerobytes() as usize
    } == crypto_box_curve25519xsalsa20poly1305_ZEROBYTES)
}
#[test]
fn test_crypto_box_curve25519xsalsa20poly1305_boxzerobytes() {
    assert!(unsafe {
        crypto_box_curve25519xsalsa20poly1305_boxzerobytes() as usize
    } == crypto_box_curve25519xsalsa20poly1305_BOXZEROBYTES)
}
#[test]
fn test_crypto_box_curve25519xsalsa20poly1305_macbytes() {
    assert!(unsafe {
        crypto_box_curve25519xsalsa20poly1305_macbytes() as usize
    } == crypto_box_curve25519xsalsa20poly1305_MACBYTES)
}

// scalarmult
#[test]
fn test_crypto_scalarmult_curve25519_bytes() {
    assert!(unsafe {
        crypto_scalarmult_curve25519_bytes() as usize
    } == crypto_scalarmult_curve25519_BYTES)
}
#[test]
fn test_crypto_scalarmult_curve25519_scalarbytes() {
    assert!(unsafe {
        crypto_scalarmult_curve25519_scalarbytes() as usize
    } == crypto_scalarmult_curve25519_SCALARBYTES)
}

// sign
#[test]
fn test_crypto_sign_ed25519_bytes() {
    assert!(unsafe {
        crypto_sign_ed25519_bytes() as usize
    } == crypto_sign_ed25519_BYTES)
}
#[test]
fn test_crypto_sign_ed25519_seedbytes() {
    assert!(unsafe {
        crypto_sign_ed25519_seedbytes() as usize
    } == crypto_sign_ed25519_SEEDBYTES)
}
#[test]
fn test_crypto_sign_ed25519_publickeybytes() {
    assert!(unsafe {
        crypto_sign_ed25519_publickeybytes() as usize
    } == crypto_sign_ed25519_PUBLICKEYBYTES)
}
#[test]
fn test_crypto_sign_ed25519_secretkeybytes() {
    assert!(unsafe {
        crypto_sign_ed25519_secretkeybytes() as usize
    } == crypto_sign_ed25519_SECRETKEYBYTES)
}

#[test]
fn test_crypto_sign_edwards25519sha512batch_bytes() {
    assert!(unsafe {
        crypto_sign_edwards25519sha512batch_bytes() as usize
    } == crypto_sign_edwards25519sha512batch_BYTES)
}
#[test]
fn test_crypto_sign_edwards25519sha512batch_publickeybytes() {
    assert!(unsafe {
        crypto_sign_edwards25519sha512batch_publickeybytes() as usize
    } == crypto_sign_edwards25519sha512batch_PUBLICKEYBYTES)
}
#[test]
fn test_crypto_sign_edwards25519sha512batch_secretkeybytes() {
    assert!(unsafe {
        crypto_sign_edwards25519sha512batch_secretkeybytes() as usize
    } == crypto_sign_edwards25519sha512batch_SECRETKEYBYTES)
}

// shorthash
#[test]
fn test_crypto_shorthash_siphash24_bytes() {
    assert!(unsafe {
        crypto_shorthash_siphash24_bytes() as usize
    } == crypto_shorthash_siphash24_BYTES)
}
#[test]
fn test_crypto_shorthash_siphash24_keybytes() {
    assert!(unsafe {
        crypto_shorthash_siphash24_keybytes() as usize
    } == crypto_shorthash_siphash24_KEYBYTES)
}

// secretbox
#[test]
fn test_crypto_secretbox_xsalsa20poly1305_keybytes() {
    assert!(unsafe {
        crypto_secretbox_xsalsa20poly1305_keybytes() as usize
    } == crypto_secretbox_xsalsa20poly1305_KEYBYTES)
}
#[test]
fn test_crypto_secretbox_xsalsa20poly1305_noncebytes() {
    assert!(unsafe {
        crypto_secretbox_xsalsa20poly1305_noncebytes() as usize
    } == crypto_secretbox_xsalsa20poly1305_NONCEBYTES)
}
#[test]
fn test_crypto_secretbox_xsalsa20poly1305_zerobytes() {
    assert!(unsafe {
        crypto_secretbox_xsalsa20poly1305_zerobytes() as usize
    } == crypto_secretbox_xsalsa20poly1305_ZEROBYTES)
}
#[test]
fn test_crypto_secretbox_xsalsa20poly1305_boxzerobytes() {
    assert!(unsafe {
        crypto_secretbox_xsalsa20poly1305_boxzerobytes() as usize
    } == crypto_secretbox_xsalsa20poly1305_BOXZEROBYTES)
}
#[test]
fn test_crypto_secretbox_xsalsa20poly1305_macbytes() {
    assert!(unsafe {
        crypto_secretbox_xsalsa20poly1305_macbytes() as usize
    } == crypto_secretbox_xsalsa20poly1305_MACBYTES)
}
