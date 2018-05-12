#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

include!(concat!(env!("OUT_DIR"), "/sodium_bindings.rs"));

// Tests

include!("crypto_aead_chacha20poly1305.rs");

include!("crypto_auth.rs");
include!("crypto_auth_hmacsha256.rs");
include!("crypto_auth_hmacsha512.rs");
include!("crypto_auth_hmacsha512256.rs");

include!("crypto_box.rs");
include!("crypto_box_curve25519xsalsa20poly1305.rs");

include!("crypto_core_hsalsa20.rs");
include!("crypto_core_salsa20.rs");
include!("crypto_core_salsa2012.rs");
include!("crypto_core_salsa208.rs");

include!("crypto_generichash.rs");
include!("crypto_generichash_blake2b.rs");

include!("crypto_hash.rs");
include!("crypto_hash_sha256.rs");
include!("crypto_hash_sha512.rs");

include!("crypto_onetimeauth.rs");
include!("crypto_onetimeauth_poly1305.rs");

include!("crypto_pwhash_scryptsalsa208sha256.rs");

include!("crypto_scalarmult.rs");
include!("crypto_scalarmult_curve25519.rs");

include!("crypto_secretbox.rs");
include!("crypto_secretbox_xsalsa20poly1305.rs");
include!("crypto_shorthash_siphash24.rs");
include!("crypto_sign_ed25519.rs");

include!("crypto_stream.rs");
include!("crypto_stream_chacha20.rs");
include!("crypto_stream_salsa20.rs");
include!("crypto_stream_salsa2012.rs");
include!("crypto_stream_salsa208.rs");
include!("crypto_stream_xsalsa20.rs");
include!("crypto_stream_xchacha20.rs");

include!("crypto_verify_16.rs");
include!("crypto_verify_32.rs");
include!("crypto_verify_64.rs");

include!("crypto_kx.rs");
