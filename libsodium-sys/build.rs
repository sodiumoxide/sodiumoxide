use std::env;
extern crate pkg_config;

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

}
