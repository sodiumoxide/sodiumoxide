// version.h

extern {
    pub fn sodium_version_string() -> *const c_char;
    pub fn sodium_library_version_major() -> c_int;
    pub fn sodium_library_version_minor() -> c_int;
}
