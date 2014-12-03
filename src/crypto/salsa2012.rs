/*!
`crypto_stream_salsa2012` (Salsa20/12), a particular cipher specified in
[Cryptography in NaCl](http://nacl.cr.yp.to/valid.html), Section 7.  This
cipher is conjectured to meet the standard notion of unpredictability.
*/
use ffi;
use libc::c_ulonglong;
use std::intrinsics::volatile_set_memory;
use randombytes::randombytes_into;

pub const KEYBYTES: uint = ffi::crypto_stream_salsa2012_KEYBYTES as uint;
pub const NONCEBYTES: uint = ffi::crypto_stream_salsa2012_NONCEBYTES as uint;

stream_module!(crypto_stream_salsa2012, crypto_stream_salsa2012_xor)
