/*!
`AES 128` in `CTR`-mode
This cipher is conjectured to meet the standard notion of
unpredictability.
*/
use libc::{c_ulonglong, c_int};
use std::intrinsics::volatile_set_memory;
use randombytes::randombytes_into;

stream_module!(crypto_stream_aes128ctr, crypto_stream_aes128ctr_xor, 16, 16)
