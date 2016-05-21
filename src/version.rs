//! Libsodium version functions
use ffi;
use std::ffi::CStr;

/// `version_string()` returns the version string from libsodium.
pub fn version_string() -> &'static str {
    let version = unsafe {
        CStr::from_ptr(ffi::sodium_version_string())
    };
    version.to_str().unwrap()
}

#[cfg(test)]
mod test {
    #[test]
    fn test_version_string() {
        use version::version_string;
        assert!(!version_string().is_empty());
    }
}
