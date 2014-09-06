/*!
`crypto_stream_salsa208` (Salsa20/8), a particular cipher specified in
[Cryptography in NaCl](http://nacl.cr.yp.to/valid.html), Section 7.  This
cipher is conjectured to meet the standard notion of unpredictability.
*/
use libc::{c_ulonglong, c_int, c_void};
use libc::types::os::arch::c95::size_t;
use randombytes::randombytes_into;

stream_module!(crypto_stream_salsa208, crypto_stream_salsa208_xor, 32, 8)
