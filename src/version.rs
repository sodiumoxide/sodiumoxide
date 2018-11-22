//! Libsodium version functions

use ffi;
use std::ffi::CStr;

/// `version_string()` returns the version string from libsodium.
pub fn version_string() -> &'static str {
    let version = unsafe { CStr::from_ptr(ffi::sodium_version_string()) };
    unwrap!(version.to_str())
}

/// `version_major()` returns the major version from libsodium.
pub fn version_major() -> usize {
    unsafe { ffi::sodium_library_version_major() as usize }
}

/// `version_minor()` returns the minor version from libsodium.
pub fn version_minor() -> usize {
    unsafe { ffi::sodium_library_version_minor() as usize }
}

#[cfg(test)]
mod test {
    #[test]
    fn test_version_string() {
        use version::version_string;
        unwrap!(::init());
        assert!(!version_string().is_empty());
    }
}
