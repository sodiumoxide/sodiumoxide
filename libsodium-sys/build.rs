extern crate pkg_config;
extern crate bindgen;

use std::env;
use std::path::PathBuf;

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
        pkg_config::find_library("libsodium").unwrap();
    }

    let bindings = bindgen::Builder::default()
        .header("wrapper.h")
        .whitelisted_function("sodium_.*")
        .whitelisted_function("crypto_.*")
        .whitelisted_function("randombytes_buf")
        .whitelisted_var("crypto_.*")
        .generate()
        .expect("Unable to generate bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
