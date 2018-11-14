extern crate bindgen;
extern crate pkg_config;

use std::env;
use std::path::PathBuf;

#[cfg(target_env = "msvc")]
extern crate vcpkg;

fn main() {
    println!("cargo:rerun-if-env-changed=SODIUM_LIB_DIR");
    println!("cargo:rerun-if-env-changed=SODIUM_INC_DIR");
    println!("cargo:rerun-if-env-changed=SODIUM_STATIC");
    if cfg!(target_env = "msvc") {
        // vcpkg requires to set env VCPKGRS_DYNAMIC
        println!("cargo:rerun-if-env-changed=VCPKGRS_DYNAMIC");
    }

    let include_dir = {
        let lib_dir_isset = env::var_os("SODIUM_LIB_DIR").is_some();
        let inc_dir_isset = env::var_os("SODIUM_INC_DIR").is_some();
        if lib_dir_isset || inc_dir_isset {
            find_libsodium_env()
        } else {
            find_libsodium_pkg()
        }
    };

    let bindings = bindgen::Builder::default()
        .header("sodium_wrapper.h")
        .whitelist_function("(sodium|crypto|randombytes)_.*")
        .whitelist_type("(sodium|crypto|randombytes)_.*")
        .whitelist_var("(sodium|crypto|randombytes)_.*")
        .clang_arg("-isystem")
        .clang_arg(include_dir)
        .generate()
        .expect("Unable to generate bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("sodium_bindings.rs"))
        .expect("Couldn't write bindings!");
}


/* Must be called when SODIUM_LIB_DIR or SODIUM_INC_DIR is set to any value
This function will set `cargo` flags.
Return: SODIUM_INC_DIR
*/
fn find_libsodium_env() -> String {
    let lib_dir = env::var("SODIUM_LIB_DIR")
        .expect("SODIUM_LIB_DIR must be set because SODIUM_INC_DIR is set. Error");
    let inc_dir = env::var("SODIUM_INC_DIR")
        .expect("SODIUM_INC_DIR must be set because SODIUM_LIB_DIR is set. Error");

    let mode = match env::var_os("SODIUM_STATIC") {
        Some(_) => "static",
        None => "dylib",
    };

    if cfg!(target_env = "msvc") {
        println!("cargo:rustc-link-lib={0}=libsodium", mode);
    } else {
        println!("cargo:rustc-link-lib={0}=sodium", mode);
    }
    println!("cargo:rustc-link-search=native={}", lib_dir);

    inc_dir
}

/* Must be called when no SODIUM_LIB_DIR and no SODIUM_INC_DIR env vars are set
This function will set `cargo` flags.
Return: the first include path from vcpkg
*/
#[cfg(target_env = "msvc")]
fn find_libsodium_pkg() -> String {
    let lib = vcpkg::probe_package("libsodium")
        .expect("Could not find libsodium on this system");
    let include_dir = lib.include_paths.get(0)
        .expect("Could not get includedir using vcpkg");
    include_dir.clone().into_os_string().into_string().ok()
        .expect("Could not get cast include_dir to String")
}

/* Must be called when no SODIUM_LIB_DIR and no SODIUM_INC_DIR env vars are set
This function will set `cargo` flags.
Return: includedir from pkg-config
*/
#[cfg(not(target_env = "msvc"))]
fn find_libsodium_pkg() -> String {
    let statik = env::var_os("SODIUM_STATIC").is_some();
    pkg_config::Config::new().statik(statik).probe("libsodium")
        .expect("Could not find libsodium on this system");
    pkg_config::get_variable("libsodium", "includedir")
        .expect("Could not get includedir using pkg-config")
}
