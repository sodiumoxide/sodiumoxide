/*!
`AES 128` in `CTR`-mode
This cipher is conjectured to meet the standard notion of
unpredictability.
*/
use ffi;
use libc::c_ulonglong;
use std::intrinsics::volatile_set_memory;
use randombytes::randombytes_into;

pub const KEYBYTES: uint = ffi::crypto_stream_aes128ctr_KEYBYTES as uint;
pub const NONCEBYTES: uint = ffi::crypto_stream_aes128ctr_NONCEBYTES as uint;

stream_module!(crypto_stream_aes128ctr, crypto_stream_aes128ctr_xor)
