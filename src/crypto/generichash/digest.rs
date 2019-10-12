use ffi::crypto_generichash_BYTES_MAX;

/// Digest-structure
///
/// This structure contains a fixed sized array as a buffer and a length to
/// represent dynamic sized digest outputs.
#[derive(Clone)]
pub struct Digest {
    pub(super) len: usize,
    pub(super) data: [u8; crypto_generichash_BYTES_MAX as usize],
}
