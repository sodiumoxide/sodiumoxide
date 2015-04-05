use std::env;

fn main () {
    if let Some(lib_dir) = env::var("SODIUM_LIB_DIR").ok() {
    	println!("cargo:rustc-flags=-L native={}", lib_dir);
    }

    let mode = if env::var_os("SODIUM_STATIC").is_some() {
    	"static"
    } else {
    	"dylib"
    };

    println!("cargo:rustc-flags=-l {0}=sodium", mode);
}
