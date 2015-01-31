/*!
`AES 128` in `CTR`-mode
This cipher is conjectured to meet the standard notion of
unpredictability.
*/
use ffi::{crypto_stream_aes128ctr,
          crypto_stream_aes128ctr_xor,
          crypto_stream_aes128ctr_KEYBYTES,
          crypto_stream_aes128ctr_NONCEBYTES};
use libc::c_ulonglong;
use std::intrinsics::volatile_set_memory;
use std::iter::repeat;
use std::ops::{Index, Range, RangeFrom, RangeFull, RangeTo};
use randombytes::randombytes_into;

stream_module!(crypto_stream_aes128ctr,
               crypto_stream_aes128ctr_xor,
               crypto_stream_aes128ctr_KEYBYTES,
               crypto_stream_aes128ctr_NONCEBYTES);
