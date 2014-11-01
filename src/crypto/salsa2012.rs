/*!
`crypto_stream_salsa2012` (Salsa20/12), a particular cipher specified in
[Cryptography in NaCl](http://nacl.cr.yp.to/valid.html), Section 7.  This
cipher is conjectured to meet the standard notion of unpredictability.
*/
#[cfg(test)]
extern crate test;
use libc::{c_ulonglong, c_int};
use std::intrinsics::volatile_set_memory;
use randombytes::randombytes_into;

stream_module!(crypto_stream_salsa2012, crypto_stream_salsa2012_xor, 32, 8)
