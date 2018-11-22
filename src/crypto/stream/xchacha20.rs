//! `xchacha20`. The same construction as `xsalsa20` but using
//! `chacha20` instead of `salsa20` as the underlying stream cipher.
//! This cipher is conjectured to meet the standard notion of
//! unpredictability.
use ffi::{
    crypto_stream_xchacha20, crypto_stream_xchacha20_KEYBYTES, crypto_stream_xchacha20_NONCEBYTES,
    crypto_stream_xchacha20_xor, crypto_stream_xchacha20_xor_ic,
};

stream_module!(
    crypto_stream_xchacha20,
    crypto_stream_xchacha20_xor,
    crypto_stream_xchacha20_xor_ic,
    crypto_stream_xchacha20_KEYBYTES,
    crypto_stream_xchacha20_NONCEBYTES
);
