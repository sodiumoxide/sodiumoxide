/*!
`crypto_stream_salsa208` (Salsa20/8), a particular cipher specified in
[Cryptography in NaCl](http://nacl.cr.yp.to/valid.html), Section 7.  This
cipher is conjectured to meet the standard notion of unpredictability.
*/
use ffi::{crypto_stream_salsa208,
          crypto_stream_salsa208_xor,
          crypto_stream_salsa208_KEYBYTES,
          crypto_stream_salsa208_NONCEBYTES};
use libc::c_ulonglong;
use std::intrinsics::volatile_set_memory;
use std::iter::repeat;
use randombytes::randombytes_into;

stream_module!(crypto_stream_salsa208,
               crypto_stream_salsa208_xor,
               crypto_stream_salsa208_KEYBYTES as usize,
               crypto_stream_salsa208_NONCEBYTES as usize);
