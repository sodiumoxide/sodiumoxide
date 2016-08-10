#[macro_use]
extern crate unwrap;

#[cfg(not(feature = "get-libsodium"))]
extern crate pkg_config;

#[cfg(not(feature = "get-libsodium"))]
fn main() {
    use std::env;

    if let Ok(lib_dir) = env::var("SODIUM_LIB_DIR") {

        println!("cargo:rustc-flags=-L native={}", lib_dir);

        let mode = match env::var_os("SODIUM_STATIC") {
            Some(_) => "static",
            None => "dylib",
        };
        println!("cargo:rustc-flags=-l {0}=sodium", mode);

    } else {

        unwrap!(pkg_config::find_library("libsodium"));

    }

}



#[cfg(feature = "get-libsodium")]
extern crate gcc;
#[cfg(feature = "get-libsodium")]
extern crate flate2;
#[cfg(feature = "get-libsodium")]
extern crate tar;

#[cfg(feature = "get-libsodium")]
const VERSION: &'static str = "1.0.11";

#[cfg(feature = "get-libsodium")]
fn get_install_dir() -> String {
    use std::env;
    unwrap!(env::var("OUT_DIR")) + "/installed"
}

#[cfg(all(windows, feature = "get-libsodium"))]
fn main() {
    use std::fs::{self, File};
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use flate2::read::GzDecoder;
    use tar::Archive;

    if cfg!(target_env = "msvc") {
        panic!("This feature currently can't be used with MSVC builds.");
    }

    // Download gz tarball
    let basename = "libsodium-".to_string() + VERSION;
    let gz_filename = basename.clone() + "-mingw.tar.gz";
    let url = "https://download.libsodium.org/libsodium/releases/".to_string() + &gz_filename;
    let install_dir = get_install_dir();
    let gz_path = install_dir.clone() + "/" + &gz_filename;
    unwrap!(fs::create_dir_all(&install_dir));

    let command = "(New-Object System.Net.WebClient).DownloadFile(\"".to_string() + &url +
                  "\", \"" + &gz_path + "\")";
    let download_output = Command::new("powershell")
        .arg("-Command")
        .arg(&command)
        .output()
        .unwrap_or_else(|error| {
            panic!("Failed to run powershell download command: {}", error);
        });
    if !download_output.status.success() {
        panic!("\n{}\n{}\n",
               String::from_utf8_lossy(&download_output.stdout),
               String::from_utf8_lossy(&download_output.stderr));
    }

    // Unpack the tarball
    let gz_archive = unwrap!(File::open(&gz_path));
    let gz_decoder = unwrap!(GzDecoder::new(gz_archive));
    let mut archive = Archive::new(gz_decoder);

    // Extract just the appropriate version of libsodium.a to the install path
    let unpacked_lib = if cfg!(target_pointer_width = "32") {
        Path::new("libsodium-win32/lib/libsodium.a")
    } else if cfg!(target_pointer_width = "64") {
        Path::new("libsodium-win64/lib/libsodium.a")
    } else {
        panic!("target_pointer_width not 32 or 64")
    };

    let mut entries = unwrap!(archive.entries());
    let mut archive_entry = unwrap!(unwrap!(entries
            .find(|entry| unwrap!(unwrap!(entry.as_ref()).path()) == unpacked_lib)));
    let _ = unwrap!(archive_entry.unpack(&(install_dir.to_string() + "/libsodium.a")));

    // Clean up
    let _ = fs::remove_file(gz_path);

    // Get path to gcc in order to guess location of libpthread.a
    let where_output = Command::new("where")
        .arg(gcc::Config::new().get_compiler().path())
        .output()
        .unwrap_or_else(|error| {
            panic!("Failed to run where command: {}", error);
        });
    if !where_output.status.success() {
        panic!("\n{}\n{}\n",
               String::from_utf8_lossy(&where_output.stdout),
               String::from_utf8_lossy(&where_output.stderr));
    }
    let compiler_path_as_string = String::from_utf8_lossy(&where_output.stdout);
    let compiler_path = PathBuf::from(compiler_path_as_string.trim());
    let mingw_path = unwrap!(unwrap!(compiler_path.parent()).parent());
    let lib_path = if cfg!(target_pointer_width = "32") {
        mingw_path.join("lib")
    } else {
        mingw_path.join("x86_64-w64-mingw32").join("lib")
    };

    println!("cargo:rustc-link-lib=static=sodium");
    println!("cargo:rustc-link-lib=pthread");
    println!("cargo:rustc-link-search=native={}", install_dir);
    println!("cargo:rustc-link-search=native={}", lib_path.display());
}



#[cfg(all(not(windows), feature = "get-libsodium"))]
fn main() {
    use std::env;
    use std::fs::{self, File};
    use std::process::Command;
    use flate2::read::GzDecoder;
    use tar::Archive;

    // Download gz tarball
    let basename = "libsodium-".to_string() + VERSION;
    let gz_filename = basename.clone() + ".tar.gz";
    let url = "https://download.libsodium.org/libsodium/releases/".to_string() + &gz_filename;
    let mut install_dir = get_install_dir();
    let mut source_dir = unwrap!(env::var("OUT_DIR")) + "/source";
    // Avoid issues with paths containing spaces by falling back to using /tmp
    let target = unwrap!(env::var("TARGET"));
    if install_dir.contains(" ") {
        install_dir = "/tmp/".to_string() + &basename + "/" + &target + "/installed";
        source_dir = "/tmp/".to_string() + &basename + "/" + &target + "/source";
    }
    let gz_path = source_dir.clone() + "/" + &gz_filename;
    unwrap!(fs::create_dir_all(&install_dir));
    unwrap!(fs::create_dir_all(&source_dir));

    let curl_output = Command::new("curl")
        .arg(&url)
        .arg("-o")
        .arg(&gz_path)
        .output()
        .unwrap_or_else(|error| {
            panic!("Failed to run curl command: {}", error);
        });
    if !curl_output.status.success() {
        panic!("\n{}\n{}\n",
               String::from_utf8_lossy(&curl_output.stdout),
               String::from_utf8_lossy(&curl_output.stderr));
    }

    // Unpack the tarball
    let gz_archive = unwrap!(File::open(&gz_path));
    let gz_decoder = unwrap!(GzDecoder::new(gz_archive));
    let mut archive = Archive::new(gz_decoder);
    unwrap!(archive.unpack(&source_dir));
    source_dir.push_str(&format!("/{}", basename));

    // Clean up
    let _ = fs::remove_file(gz_path);

    // Run `./configure`
    let gcc = gcc::Config::new();
    let cc = format!("{}", gcc.get_compiler().path().display());
    let prefix_arg = format!("--prefix={}", install_dir);
    let host = unwrap!(env::var("HOST"));
    let host_arg = format!("--host={}", target);

    let configure_output = Command::new("./configure")
        .current_dir(&source_dir)
        .env("CC", &cc)
        .arg(&prefix_arg)
        .arg(&host_arg)
        .arg("--enable-shared=no")
        .output()
        .unwrap_or_else(|error| {
            panic!("Failed to run './configure': {}", error);
        });
    if !configure_output.status.success() {
        panic!("\n{}\n{}\n",
               String::from_utf8_lossy(&configure_output.stdout),
               String::from_utf8_lossy(&configure_output.stderr));
    }

    // Run `make check`, or `make all` if we're cross-compiling
    let j_arg = format!("-j{}", unwrap!(env::var("NUM_JOBS")));
    let make_arg = if target == host {
        "check"
    } else {
        "all"
    };
    let make_output = Command::new("make")
        .current_dir(&source_dir)
        .env("V", "1")
        .arg(make_arg)
        .arg(&j_arg)
        .output()
        .unwrap_or_else(|error| {
            panic!("Failed to run 'make check': {}", error);
        });
    if !make_output.status.success() {
        panic!("\n{}\n{}\n{}\n",
               String::from_utf8_lossy(&configure_output.stdout),
               String::from_utf8_lossy(&make_output.stdout),
               String::from_utf8_lossy(&make_output.stderr));
    }

    // Run `make install`
    let install_output = Command::new("make")
        .current_dir(&source_dir)
        .arg("install")
        .output()
        .unwrap_or_else(|error| {
            panic!("Failed to run 'make install': {}", error);
        });
    if !install_output.status.success() {
        panic!("\n{}\n{}\n{}\n{}\n",
               String::from_utf8_lossy(&configure_output.stdout),
               String::from_utf8_lossy(&make_output.stdout),
               String::from_utf8_lossy(&install_output.stdout),
               String::from_utf8_lossy(&install_output.stderr));
    }

    println!("cargo:rustc-link-lib=static=sodium");
    println!("cargo:rustc-link-search=native={}/lib", install_dir);
}
