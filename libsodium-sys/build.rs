#[cfg(not(windows))]
extern crate cc;
extern crate http_req;
#[cfg(target_env = "msvc")]
extern crate libc;
#[cfg(not(target_env = "msvc"))]
extern crate libflate;
extern crate pkg_config;
extern crate sha2;
#[cfg(not(target_env = "msvc"))]
extern crate tar;
#[cfg(target_env = "msvc")]
extern crate vcpkg;
#[cfg(target_env = "msvc")]
extern crate zip;

use http_req::request;
use sha2::{Digest, Sha256};
use std::env;
use std::fs;
use std::io::Cursor;
use std::path::Path;

static DOWNLOAD_BASE_URL: &'static str = "https://download.libsodium.org/libsodium/releases/";
static VERSION: &'static str = "1.0.17";

#[cfg(target_env = "msvc")] // libsodium-<VERSION>-msvc.zip
static SHA256: &'static str = "d0ccc129253d0d51f09f8d030129041eb56fc3f488a0206babff2ef0b1752368";

#[cfg(all(windows, not(target_env = "msvc")))] // libsodium-<VERSION>-mingw.tar.gz
static SHA256: &'static str = "3c76ab4a5033b03503331314b2f289361171d7fbbfd98886751dd7f8a8a6496f";

#[cfg(not(windows))] // libsodium-<VERSION>.tar.gz
static SHA256: &'static str = "0cc3dae33e642cc187b5ceb467e0ad0e1b51dcba577de1190e9ffa17766ac2b1";

fn main() {
    println!("cargo:rerun-if-env-changed=SODIUM_LIB_DIR");
    println!("cargo:rerun-if-env-changed=SODIUM_SHARED");
    println!("cargo:rerun-if-env-changed=SODIUM_USE_PKG_CONFIG");

    if cfg!(target_env = "msvc") {
        // vcpkg requires to set env VCPKGRS_DYNAMIC
        println!("cargo:rerun-if-env-changed=VCPKGRS_DYNAMIC");
    }
    if cfg!(not(windows)) {
        println!("cargo:rerun-if-env-changed=SODIUM_DISABLE_PIE");
    }

    if env::var("SODIUM_STATIC").is_ok() {
        panic!("SODIUM_STATIC is deprecated. Use SODIUM_SHARED instead.");
    }

    let lib_dir_isset = env::var("SODIUM_LIB_DIR").is_ok();
    let use_pkg_isset = if cfg!(feature = "use-pkg-config") {
        true
    } else {
        env::var("SODIUM_USE_PKG_CONFIG").is_ok()
    };
    let shared_isset = env::var("SODIUM_SHARED").is_ok();

    if lib_dir_isset && use_pkg_isset {
        panic!("SODIUM_LIB_DIR is incompatible with SODIUM_USE_PKG_CONFIG. Set the only one env variable");
    }

    if lib_dir_isset {
        find_libsodium_env();
    } else if use_pkg_isset {
        if shared_isset {
            println!("cargo:warning=SODIUM_SHARED has no effect with SODIUM_USE_PKG_CONFIG");
        }

        find_libsodium_pkg();
    } else {
        if shared_isset {
            println!(
                "cargo:warning=SODIUM_SHARED has no effect for building libsodium from source"
            );
        }

        build_libsodium();
    }
}

/* Must be called when SODIUM_LIB_DIR is set to any value
This function will set `cargo` flags.
*/
fn find_libsodium_env() {
    let lib_dir = env::var("SODIUM_LIB_DIR").unwrap(); // cannot fail

    println!("cargo:rustc-link-search=native={}", lib_dir);
    let mode = if env::var("SODIUM_SHARED").is_ok() {
        "dylib"
    } else {
        "static"
    };
    let name = if cfg!(target_env = "msvc") {
        "libsodium"
    } else {
        "sodium"
    };
    println!("cargo:rustc-link-lib={}={}", mode, name);
    println!(
        "cargo:warning=Using unknown libsodium version.  This crate is tested against \
         {} and may not be fully compatible with other versions.",
        VERSION
    );
}

/* Must be called when no SODIUM_USE_PKG_CONFIG env var is set
This function will set `cargo` flags.
*/
#[cfg(target_env = "msvc")]
fn find_libsodium_pkg() {
    match vcpkg::probe_package("libsodium") {
        Ok(_) => {
            println!(
                "cargo:warning=Using unknown libsodium version.  This crate is tested against \
                 {} and may not be fully compatible with other versions.",
                VERSION
            );
        }
        Err(e) => {
            panic!(format!("Error: {:?}", e));
        }
    };
}

/* Must be called when SODIUM_USE_PKG_CONFIG env var is set
This function will set `cargo` flags.
*/
#[cfg(not(target_env = "msvc"))]
fn find_libsodium_pkg() {
    match pkg_config::Config::new().probe("libsodium") {
        Ok(lib) => {
            if lib.version != VERSION {
                println!(
                    "cargo:warning=Using libsodium version {}.  This crate is tested against {} \
                     and may not be fully compatible with {}.",
                    lib.version, VERSION, lib.version
                );
            }
        }
        Err(e) => {
            panic!(format!("Error: {:?}", e));
        }
    }
}

/// Download the specified URL into a buffer which is returned.
fn download(url: &str, expected_hash: &str) -> Cursor<Vec<u8>> {
    // Send GET request
    let mut response_body = Vec::new();
    let response = request::get(url, &mut response_body).unwrap();

    // Only accept 2xx status codes
    if !response.status_code().is_success() {
        panic!("Download error: HTTP {}", response.status_code());
    }

    // Check the SHA-256 hash of the downloaded file is as expected
    let hash = Sha256::digest(&response_body);
    assert_eq!(
        &format!("{:x}", hash),
        expected_hash,
        "\n\nDownloaded libsodium file failed hash check.\n\n"
    );

    Cursor::new(response_body)
}

fn get_install_dir() -> String {
    env::var("OUT_DIR").unwrap() + "/installed"
}

#[cfg(target_env = "msvc")]
fn build_libsodium() {
    use libc::S_IFDIR;
    use std::fs::File;
    use std::io::{Read, Write};
    use zip::ZipArchive;

    // Download zip file
    let install_dir = get_install_dir();
    let lib_install_dir = Path::new(&install_dir).join("lib");
    fs::create_dir_all(&lib_install_dir).unwrap();
    let url = format!("{}libsodium-{}-msvc.zip", DOWNLOAD_BASE_URL, VERSION);
    let compressed_file = download(&url, SHA256);

    // Unpack the zip file
    let mut zip_archive = ZipArchive::new(compressed_file).unwrap();

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
        let mut entry = zip_archive.by_index(i).unwrap();
        let entry_name = entry.name().to_string();
        let entry_path = Path::new(&entry_name);
        let opt_install_path = if entry_path.starts_with("include") {
            let is_dir = (entry.unix_mode().unwrap() & S_IFDIR as u32) != 0;
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
            assert_eq!(entry.size(), entry.read_to_end(&mut buffer).unwrap() as u64);
            let mut file = File::create(&full_install_path).unwrap();
            file.write_all(&buffer).unwrap();
        }
    }

    println!("cargo:rustc-link-lib=static=libsodium");
    println!(
        "cargo:rustc-link-search=native={}",
        lib_install_dir.display()
    );
}

#[cfg(all(windows, not(target_env = "msvc")))]
fn build_libsodium() {
    use libflate::gzip::Decoder;
    use tar::Archive;

    // Download gz tarball
    let install_dir = get_install_dir();
    let lib_install_dir = Path::new(&install_dir).join("lib");
    fs::create_dir_all(&lib_install_dir).unwrap();
    let url = format!("{}libsodium-{}-mingw.tar.gz", DOWNLOAD_BASE_URL, VERSION);
    let compressed_file = download(&url, SHA256);

    // Unpack the tarball
    let gz_decoder = Decoder::new(compressed_file).unwrap();
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
    let entries = archive.entries().unwrap();
    for entry_result in entries {
        let mut entry = entry_result.unwrap();
        let entry_path = entry.path().unwrap().to_path_buf();
        let full_install_path = if entry_path.starts_with(&unpacked_include) {
            let include_file = entry_path.strip_prefix(arch_path).unwrap();
            Path::new(&install_dir).join(include_file)
        } else if entry_path == unpacked_lib {
            lib_install_dir.join("libsodium.a")
        } else {
            continue;
        };
        entry.unpack(full_install_path).unwrap();
    }

    println!("cargo:rustc-link-lib=static=sodium");
    println!(
        "cargo:rustc-link-search=native={}",
        lib_install_dir.display()
    );
}

#[cfg(not(windows))]
fn build_libsodium() {
    use libflate::gzip::Decoder;
    use std::process::Command;
    use std::str;
    use tar::Archive;

    // Determine build target triple
    let target = env::var("TARGET").unwrap();

    // Determine filenames and download URLs
    let basename = format!("libsodium-{}", VERSION);
    let url = format!("{}{}.tar.gz", DOWNLOAD_BASE_URL, basename);

    // Determine source and install dir
    let mut install_dir = get_install_dir();
    let mut source_dir = env::var("OUT_DIR").unwrap() + "/source";

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
    fs::create_dir_all(&install_dir).unwrap();
    fs::create_dir_all(&source_dir).unwrap();

    // Download sources
    let compressed_file = download(&url, SHA256);

    // Unpack the tarball
    let gz_decoder = Decoder::new(compressed_file).unwrap();
    let mut archive = Archive::new(gz_decoder);
    archive.unpack(&source_dir).unwrap();
    source_dir.push_str(&format!("/{}", basename));

    // Decide on CC, CFLAGS and the --host configure argument
    let build = cc::Build::new();
    let mut compiler = build.get_compiler().path().to_str().unwrap().to_string();
    let mut cflags = env::var("CFLAGS").unwrap_or(String::default());
    cflags += " -O2";
    let host_arg;
    let cross_compiling;
    let help;
    if target.contains("-ios") {
        // Determine Xcode directory path
        let xcode_select_output = Command::new("xcode-select").arg("-p").output().unwrap();
        if !xcode_select_output.status.success() {
            panic!("Failed to run xcode-select -p");
        }
        let xcode_dir = str::from_utf8(&xcode_select_output.stdout)
            .unwrap()
            .trim()
            .to_string();

        // Determine SDK directory paths
        let sdk_dir_simulator = Path::new(&xcode_dir)
            .join("Platforms/iPhoneSimulator.platform/Developer/SDKs/iPhoneSimulator.sdk")
            .to_str()
            .unwrap()
            .to_string();
        let sdk_dir_ios = Path::new(&xcode_dir)
            .join("Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS.sdk")
            .to_str()
            .unwrap()
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
        let host = env::var("HOST").unwrap();
        host_arg = format!("--host={}", target);
        cross_compiling = target != host;
        help = if cross_compiling {
            "***********************************************************\n\
             Possible missing dependencies.\n\
             See https://github.com/sodiumoxide/sodiumoxide#cross-compiling\n\
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
    if env::var("SODIUM_DISABLE_PIE").is_ok() {
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
    let j_arg = format!("-j{}", env::var("NUM_JOBS").unwrap());
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

    println!("cargo:rustc-link-lib=static=sodium");
    println!("cargo:rustc-link-search=native={}/lib", install_dir);
}
