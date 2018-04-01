use std::env;
extern crate pkg_config;

#[cfg(target_env = "msvc")]
extern crate vcpkg;

fn main() {

    println!("cargo:rerun-if-env-changed=SODIUM_LIB_DIR");
    println!("cargo:rerun-if-env-changed=SODIUM_STATIC");
    if let Ok(lib_dir) = env::var("SODIUM_LIB_DIR") {

        println!("cargo:rustc-link-search=native={}", lib_dir);

        let mode = match env::var_os("SODIUM_STATIC") {
            Some(_) => "static",
            None => "dylib",
        };
        println!("cargo:rustc-link-lib={0}=sodium", mode);

    } else {
        if pkg_config::probe_library("libsodium").is_ok() {
            // pkg_config did everything for us
            return
        } else if try_vcpkg() {
            return;
        }
    }
}

#[cfg(target_env = "msvc")]
fn try_vcpkg() -> bool {
    if vcpkg::Config::new()
        .lib_name("libsodium")
        .probe("libsodium")
        .is_ok() {
        // found the static library - vcpkg did everything for us
        return true;
    } else if vcpkg::probe_package("libsodium").is_ok() {
        // found the dynamic library - vcpkg did everything for us
        return true;
    }
    false
}

#[cfg(not(target_env = "msvc"))]
fn try_vcpkg() -> bool {
    false
}