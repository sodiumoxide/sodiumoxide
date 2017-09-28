extern crate pkg_config;

use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    // Use already existing libsodium install if pkgconfig can find one
    match pkg_config::find_library("libsodium") {
        Ok(_) => return,
        Err(e) => {
            println!(
                "Couldn't find libsodium from pkgconfig ({:?}), compiling it from source...",
                e
            )
        }
    }

    // Fall back to compiling libsodium from sources

    // Directory to install libsodium into
    let target_dir = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR env variable"));

    // Current working directory (where Cargo.toml is)
    let cwd = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR env variable"));

    // Directory pointing to libsodium sources
    let libsodium_dir = cwd.join("libsodium");

    // Directory used while building libsodium
    let build_dir = {
        let dir = target_dir.join("libsodium_build");
        std::fs::create_dir_all(&dir).expect("create_dir_all");
        dir
    };

    if !Path::new("libsodium/.git").exists() {
        let git_toplevel = cwd.parent().expect("libsodium_dir parent");
        Command::new("git")
            .current_dir(&git_toplevel)
            .args(&["submodule", "update", "--init"])
            .status()
            .expect("git submodule update");
    }

    Command::new(libsodium_dir.join("autogen.sh"))
        .current_dir(&libsodium_dir)
        .status()
        .expect("autogen.sh");

    Command::new(libsodium_dir.join("configure"))
        .current_dir(&build_dir)
        .arg(format!("--prefix={}", target_dir.display()))
        .args(&["--enable-static", "--disable-shared"])
        .status()
        .expect("configure");

    Command::new("make")
        .current_dir(&build_dir)
        .status()
        .expect("make");

    Command::new("make")
        .current_dir(&build_dir)
        .arg("check")
        .status()
        .expect("make check");

    Command::new("make")
        .current_dir(&build_dir)
        .arg("install")
        .status()
        .expect("make install");

    println!("cargo:root={}", target_dir.display());
    println!("cargo:rustc-link-lib=static=sodium");
    println!("cargo:include={}/include", target_dir.display());
    println!(
        "cargo:rustc-link-search=native={}/lib",
        target_dir.display()
    );
}
