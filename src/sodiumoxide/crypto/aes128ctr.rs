/*!
`AES 128` in `CTR`-mode
This cipher is conjectured to meet the standard notion of
unpredictability.
*/
use libc::{c_ulonglong, c_int, c_void};
use libc::types::os::arch::c95::size_t;
use randombytes::randombytes_into;

stream_module!(crypto_stream_aes128ctr, crypto_stream_aes128ctr_xor, 16, 16)
