extern crate bindgen;
#[cfg(not(windows))]
extern crate cc;
#[cfg(not(target_env = "msvc"))]
extern crate flate2;
extern crate http_req;
#[cfg(target_env = "msvc")]
extern crate libc;
extern crate pkg_config;
extern crate sha2;
#[cfg(not(target_env = "msvc"))]
extern crate tar;
#[macro_use]
extern crate unwrap;
#[cfg(target_env = "msvc")]
extern crate vcpkg;
#[cfg(target_env = "msvc")]
extern crate zip;

use http_req::request;
use sha2::{Digest, Sha256};
use std::env;
use std::fs;
use std::io::Cursor;
use std::path::{Path, PathBuf};

static DOWNLOAD_BASE_URL: &'static str = "https://download.libsodium.org/libsodium/releases/";
static VERSION: &'static str = "1.0.16";

#[cfg(target_env = "msvc")] // libsodium-<VERSION>-msvc.zip
static SHA256: &'static str = "0580d54f57594a7cb493607cec6e7045369fb67d43623491523781e901589948";

#[cfg(all(windows, not(target_env = "msvc")))] // libsodium-<VERSION>-mingw.tar.gz
static SHA256: &'static str = "5b81a4fc5d0de36dbda7efeaf355c133d4f6cc0b4dbf69bbe46ef7f5a6baa639";

#[cfg(not(windows))] // libsodium-<VERSION>.tar.gz
static SHA256: &'static str = "eeadc7e1e1bcef09680fb4837d448fbdf57224978f865ac1c16745868fbd0533";

fn main() {
    println!("cargo:rerun-if-env-changed=SODIUM_LIB_DIR");
    println!("cargo:rerun-if-env-changed=SODIUM_INC_DIR");
    println!("cargo:rerun-if-env-changed=SODIUM_STATIC");
    println!("cargo:rerun-if-env-changed=SODIUM_FROM_SRC");

    let include_dir = {
        if env::var("SODIUM_FROM_SRC").is_ok() {
            get_libsodium()
        } else {
            match find_libsodium() {
                Some(lib) => lib,
                None => get_libsodium(),
            }
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

fn print_link(name: &str) {
    let mode = match env::var_os("SODIUM_STATIC") {
        Some(_) => "static",
        None => "dylib",
    };
    println!("cargo:rustc-link-lib={}={}", mode, name);
}

#[cfg(target_env = "msvc")]
fn find_libsodium() -> Option<String> {
    if let Ok(lib_dir) = env::var("SODIUM_LIB_DIR") {
        print_link("libsodium");
        println!("cargo:rustc-link-search=native={}", lib_dir);
    } else {
        if !try_vcpkg() {
            return None;
        }
    }

    let include_dir = env::var("SODIUM_INC_DIR")
        .ok()
        .or_else(get_vcpkg_include_path);

    include_dir
}

#[cfg(not(target_env = "msvc"))]
fn find_libsodium() -> Option<String> {
    if let Ok(lib_dir) = env::var("SODIUM_LIB_DIR") {
        print_link("sodium");
        println!("cargo:rustc-link-search=native={}", lib_dir);
    } else {
        let statik = env::var_os("SODIUM_STATIC").is_some();
        if let Err(_) = pkg_config::Config::new().statik(statik).find("libsodium") {
            return None;
        }
    }

    let include_dir =
        env::var("SODIUM_INC_DIR").or_else(|_| pkg_config::get_variable("libsodium", "includedir"));

    include_dir.ok()
}

#[cfg(target_env = "msvc")]
fn try_vcpkg() -> bool {
    vcpkg::Config::new()
        .lib_name("libsodium")
        .probe("libsodium")
        .is_ok()
        || vcpkg::probe_package("libsodium").is_ok()
}

#[cfg(target_env = "msvc")]
fn get_vcpkg_include_path() -> Option<String> {
    let lib = vcpkg::probe_package("libsodium");
    match lib {
        Ok(lib) => lib
            .include_paths
            .get(0)
            .and_then(|path| path.clone().into_os_string().into_string().ok()),
        _ => None,
    }
}

/// Download the specified URL into a buffer which is returned.
fn download(url: &str, expected_hash: &str) -> Cursor<Vec<u8>> {
    // Send GET request
    let response = unwrap!(request::get(url));

    // Only accept 2xx status codes
    if response.status_code() < 200 && response.status_code() >= 300 {
        panic!("Download error: HTTP {}", response.status_code());
    }
    let resp_body = response.body();
    let buffer = resp_body.to_vec();

    // Check the SHA-256 hash of the downloaded file is as expected
    let hash = Sha256::digest(&buffer);
    assert_eq!(
        &format!("{:x}", hash),
        expected_hash,
        "\n\nDownloaded libsodium file failed hash check.\n\n"
    );

    Cursor::new(buffer)
}

fn get_install_dir() -> String {
    unwrap!(env::var("OUT_DIR")) + "/installed"
}

#[cfg(target_env = "msvc")]
fn get_libsodium() -> String {
    use libc::S_IFDIR;
    use std::fs::File;
    use std::io::{Read, Write};
    use zip::ZipArchive;

    // Download zip file
    let install_dir = get_install_dir();
    let lib_install_dir = Path::new(&install_dir).join("lib");
    unwrap!(fs::create_dir_all(&lib_install_dir));
    let url = format!("{}libsodium-{}-msvc.zip", DOWNLOAD_BASE_URL, VERSION);
    let compressed_file = download(&url, SHA256);

    // Unpack the zip file
    let mut zip_archive = unwrap!(ZipArchive::new(compressed_file));

    // Extract just the appropriate version of libsodium.lib and headers to the install path.  For
    // now, only handle MSVC 2015.
    let arch_path = if cfg!(target_pointer_width = "32") {
        Path::new("Win32")
    } else if cfg!(target_pointer_width = "64") {
        Path::new("x64")
    } else {
        panic!("target_pointer_width not 32 or 64")
    };

    let unpacked_lib = arch_path.join("Release/v140/static/libsodium.lib");
    for i in 0..zip_archive.len() {
        let mut entry = unwrap!(zip_archive.by_index(i));
        let entry_name = entry.name().to_string();
        let entry_path = Path::new(&entry_name);
        let opt_install_path = if entry_path.starts_with("include") {
            let is_dir = (unwrap!(entry.unix_mode()) & S_IFDIR as u32) != 0;
            if is_dir {
                let _ = fs::create_dir(&Path::new(&install_dir).join(entry_path));
                None
            } else {
                Some(Path::new(&install_dir).join(entry_path))
            }
        } else if entry_path == unpacked_lib {
            Some(lib_install_dir.join("libsodium.lib"))
        } else {
            None
        };
        if let Some(full_install_path) = opt_install_path {
            let mut buffer = Vec::with_capacity(entry.size() as usize);
            assert_eq!(entry.size(), unwrap!(entry.read_to_end(&mut buffer)) as u64);
            let mut file = unwrap!(File::create(&full_install_path));
            unwrap!(file.write_all(&buffer));
        }
    }

    print_link("libsodium");
    println!(
        "cargo:rustc-link-search=native={}",
        lib_install_dir.display()
    );

    format!("{}/include", install_dir)
}

#[cfg(all(windows, not(target_env = "msvc")))]
fn get_libsodium() -> String {
    use flate2::read::GzDecoder;
    use tar::Archive;

    // Download gz tarball
    let install_dir = get_install_dir();
    let lib_install_dir = Path::new(&install_dir).join("lib");
    unwrap!(fs::create_dir_all(&lib_install_dir));
    let url = format!("{}libsodium-{}-mingw.tar.gz", DOWNLOAD_BASE_URL, VERSION);
    let compressed_file = download(&url, SHA256);

    // Unpack the tarball
    let gz_decoder = GzDecoder::new(compressed_file);
    let mut archive = Archive::new(gz_decoder);

    // Extract just the appropriate version of libsodium.a and headers to the install path
    let arch_path = if cfg!(target_pointer_width = "32") {
        Path::new("libsodium-win32")
    } else if cfg!(target_pointer_width = "64") {
        Path::new("libsodium-win64")
    } else {
        panic!("target_pointer_width not 32 or 64")
    };

    let unpacked_include = arch_path.join("include");
    let unpacked_lib = arch_path.join("lib\\libsodium.a");
    let entries = unwrap!(archive.entries());
    for entry_result in entries {
        let mut entry = unwrap!(entry_result);
        let entry_path = unwrap!(entry.path()).to_path_buf();
        let full_install_path = if entry_path.starts_with(&unpacked_include) {
            let include_file = unwrap!(entry_path.strip_prefix(arch_path));
            Path::new(&install_dir).join(include_file)
        } else if entry_path == unpacked_lib {
            lib_install_dir.join("libsodium.a")
        } else {
            continue;
        };
        unwrap!(entry.unpack(full_install_path));
    }

    print_link("sodium");
    println!(
        "cargo:rustc-link-search=native={}",
        lib_install_dir.display()
    );
    format!("{}/include", install_dir)
}

#[cfg(not(windows))]
fn get_libsodium() -> String {
    use flate2::read::GzDecoder;
    use std::process::Command;
    use std::str;
    use tar::Archive;

    // Determine build target triple
    let target = unwrap!(env::var("TARGET"));

    // Determine filenames and download URLs
    let basename = format!("libsodium-{}", VERSION);
    let url = format!("{}{}.tar.gz", DOWNLOAD_BASE_URL, basename);

    // Determine source and install dir
    let mut install_dir = get_install_dir();
    let mut source_dir = unwrap!(env::var("OUT_DIR")) + "/source";

    // Avoid issues with paths containing spaces by falling back to using a tempfile.
    // See https://github.com/jedisct1/libsodium/issues/207
    if install_dir.contains(" ") {
        let fallback_path = "/tmp/".to_string() + &basename + "/" + &target;
        install_dir = fallback_path.clone() + "/installed";
        source_dir = fallback_path.clone() + "/source";
        println!(
            "cargo:warning=The path to the usual build directory contains spaces and hence \
             can't be used to build libsodium.  Falling back to use {}.  If running `cargo \
             clean`, ensure you also delete this fallback directory",
            fallback_path
        );
    }

    // Create directories
    unwrap!(fs::create_dir_all(&install_dir));
    unwrap!(fs::create_dir_all(&source_dir));

    // Download sources
    let compressed_file = download(&url, SHA256);

    // Unpack the tarball
    let gz_decoder = GzDecoder::new(compressed_file);
    let mut archive = Archive::new(gz_decoder);
    unwrap!(archive.unpack(&source_dir));
    source_dir.push_str(&format!("/{}", basename));

    // Decide on CC, CFLAGS and the --host configure argument
    let build = cc::Build::new();
    let mut compiler = unwrap!(build.get_compiler().path().to_str()).to_string();
    let mut cflags = env::var("CFLAGS").unwrap_or(String::default());
    cflags += " -O2";
    let host_arg;
    let cross_compiling;
    let help;
    if target.contains("-ios") {
        // Determine Xcode directory path
        let xcode_select_output = unwrap!(Command::new("xcode-select").arg("-p").output());
        if !xcode_select_output.status.success() {
            panic!("Failed to run xcode-select -p");
        }
        let xcode_dir = unwrap!(str::from_utf8(&xcode_select_output.stdout))
            .trim()
            .to_string();

        // Determine SDK directory paths
        let sdk_dir_simulator = unwrap!(
            Path::new(&xcode_dir)
                .join("Platforms/iPhoneSimulator.platform/Developer/SDKs/iPhoneSimulator.sdk")
                .to_str()
        )
        .to_string();
        let sdk_dir_ios = unwrap!(
            Path::new(&xcode_dir)
                .join("Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS.sdk")
                .to_str()
        )
        .to_string();

        // Min versions
        let ios_simulator_version_min = "6.0.0";
        let ios_version_min = "6.0.0";

        // Roughly based on `dist-build/ios.sh` in the libsodium sources
        match &*target {
            "aarch64-apple-ios" => {
                cflags += " -arch arm64";
                cflags += &format!(" -isysroot {}", sdk_dir_ios);
                cflags += &format!(" -mios-version-min={}", ios_version_min);
                cflags += " -fembed-bitcode";
                host_arg = "--host=arm-apple-darwin10".to_string();
            }
            "armv7-apple-ios" => {
                cflags += " -arch armv7";
                cflags += &format!(" -isysroot {}", sdk_dir_ios);
                cflags += &format!(" -mios-version-min={}", ios_version_min);
                cflags += " -mthumb";
                host_arg = "--host=arm-apple-darwin10".to_string();
            }
            "armv7s-apple-ios" => {
                cflags += " -arch armv7s";
                cflags += &format!(" -isysroot {}", sdk_dir_ios);
                cflags += &format!(" -mios-version-min={}", ios_version_min);
                cflags += " -mthumb";
                host_arg = "--host=arm-apple-darwin10".to_string();
            }
            "i386-apple-ios" => {
                cflags += " -arch i386";
                cflags += &format!(" -isysroot {}", sdk_dir_simulator);
                cflags += &format!(" -mios-simulator-version-min={}", ios_simulator_version_min);
                host_arg = "--host=i686-apple-darwin10".to_string();
            }
            "x86_64-apple-ios" => {
                cflags += " -arch x86_64";
                cflags += &format!(" -isysroot {}", sdk_dir_simulator);
                cflags += &format!(" -mios-simulator-version-min={}", ios_simulator_version_min);
                host_arg = "--host=x86_64-apple-darwin10".to_string();
            }
            _ => panic!("Unknown iOS build target: {}", target),
        }
        cross_compiling = true;
        help = "";
    } else {
        if target.contains("i686") {
            compiler += " -m32 -maes";
            cflags += " -march=i686";
        }
        let host = unwrap!(env::var("HOST"));
        host_arg = format!("--host={}", target);
        cross_compiling = target != host;
        help = if cross_compiling {
            "***********************************************************\n\
             Possible missing dependencies.\n\
             See https://github.com/maidsafe/rust_sodium#cross-compiling\n\
             ***********************************************************\n\n"
        } else {
            ""
        };
    }

    // Run `./configure`
    let prefix_arg = format!("--prefix={}", install_dir);
    let mut configure_cmd = Command::new("./configure");
    if !compiler.is_empty() {
        configure_cmd.env("CC", &compiler);
    }
    if !cflags.is_empty() {
        configure_cmd.env("CFLAGS", &cflags);
    }
    println!("cargo:rerun-if-env-changed=RUST_SODIUM_DISABLE_PIE");
    if env::var("RUST_SODIUM_DISABLE_PIE").is_ok() {
        configure_cmd.arg("--disable-pie");
    }
    let configure_output = configure_cmd
        .current_dir(&source_dir)
        .arg(&prefix_arg)
        .arg(&host_arg)
        .arg("--enable-shared=no")
        .output()
        .unwrap_or_else(|error| {
            panic!("Failed to run './configure': {}\n{}", error, help);
        });
    if !configure_output.status.success() {
        panic!(
            "\n{:?}\nCFLAGS={}\nCC={}\n{}\n{}\n{}\n",
            configure_cmd,
            cflags,
            compiler,
            String::from_utf8_lossy(&configure_output.stdout),
            String::from_utf8_lossy(&configure_output.stderr),
            help
        );
    }

    // Run `make check`, or `make all` if we're cross-compiling
    let j_arg = format!("-j{}", unwrap!(env::var("NUM_JOBS")));
    let make_arg = if cross_compiling { "all" } else { "check" };
    let mut make_cmd = Command::new("make");
    let make_output = make_cmd
        .current_dir(&source_dir)
        .env("V", "1")
        .arg(make_arg)
        .arg(&j_arg)
        .output()
        .unwrap_or_else(|error| {
            panic!("Failed to run 'make {}': {}\n{}", make_arg, error, help);
        });
    if !make_output.status.success() {
        panic!(
            "\n{:?}\n{}\n{}\n{}\n{}",
            make_cmd,
            String::from_utf8_lossy(&configure_output.stdout),
            String::from_utf8_lossy(&make_output.stdout),
            String::from_utf8_lossy(&make_output.stderr),
            help
        );
    }

    // Run `make install`
    let mut install_cmd = Command::new("make");
    let install_output = install_cmd
        .current_dir(&source_dir)
        .arg("install")
        .output()
        .unwrap_or_else(|error| {
            panic!("Failed to run 'make install': {}", error);
        });
    if !install_output.status.success() {
        panic!(
            "\n{:?}\n{}\n{}\n{}\n{}\n",
            install_cmd,
            String::from_utf8_lossy(&configure_output.stdout),
            String::from_utf8_lossy(&make_output.stdout),
            String::from_utf8_lossy(&install_output.stdout),
            String::from_utf8_lossy(&install_output.stderr)
        );
    }

    print_link("sodium");
    println!("cargo:rustc-link-search=native={}/lib", install_dir);
    format!("{}/include", install_dir)
}
