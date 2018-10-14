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

    if let Ok(lib_dir) = env::var("SODIUM_LIB_DIR") {
        println!("cargo:rustc-link-search=native={}", lib_dir);

        let mode = match env::var_os("SODIUM_STATIC") {
            Some(_) => "static",
            None => "dylib",
        };
        if cfg!(target_env = "msvc") {
            println!("cargo:rustc-link-lib={0}=libsodium", mode);
        } else {
            println!("cargo:rustc-link-lib={0}=sodium", mode);
        }
    } else {
        if !pkg_config::probe_library("libsodium").is_ok() && !try_vcpkg() {
            panic!("Could not find libsodium on this system!")
        }
    }

    let include_dir = match env::var("SODIUM_INC_DIR") {
        Ok(dir) => dir,
        Err(_) => pkg_config::get_variable("libsodium", "includedir").unwrap_or_else(|_| {
            get_vcpkg_include_path().unwrap()
        })
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

#[cfg(target_env = "msvc")]
fn try_vcpkg() -> bool {
    vcpkg::Config::new()
        .lib_name("libsodium")
        .probe("libsodium")
        .is_ok() ||  vcpkg::probe_package("libsodium").is_ok()
}

#[cfg(not(target_env = "msvc"))]
fn try_vcpkg() -> bool {
    false
}


#[cfg(target_env = "msvc")]
fn get_vcpkg_include_path() -> Option<String> {
    let lib = vcpkg::probe_package("libsodium");
    match lib {
        Ok(lib) => lib.include_paths.get(0).and_then(|path| path.clone().into_os_string().into_string().ok()),
        _ => None,
    }

}

#[cfg(not(target_env = "msvc"))]
fn get_vcpkg_include_path() -> Option<String> {
    None
}
