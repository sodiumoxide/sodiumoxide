    use std::env::var;
use std::path::PathBuf;

const VERSION: &str = "1.0.18";

fn main() {
    if var("SODIUM_SHARED").is_ok() {
        panic!("`SODIUM_SHARED` is deprecated. Use `SODIUM_DYNAMIC` or `VCPKGRS_DYNAMIC` instead.");
    }

    if find_env() {
        return;
    }

    if find_vcpkg() {
        return;
    }

    if find_pkg_config() {
        return;
    }

    if link_prebuilt() {
        return;
    }

    if build_from_source() {
        return;
    }

    panic!("Failed to find or build libsodium. Specify `SODIUM_LIB_DIR` or enable at least one of the `pkg-config`, `vcpkg` or `cc` features.");
}

fn lib_name() -> &'static str {
    if cfg!(target_env = "msvc") {
        "libsodium"
    } else {
        "sodium"
    }
}

fn find_env() -> bool {
    println!("cargo:rerun-if-env-changed=SODIUM_LIB_DIR");

    let lib_dir = match var("SODIUM_LIB_DIR") {
        Ok(lib_dir) => lib_dir,
        _ => return false,
    };

    println!("cargo:rerun-if-env-changed=SODIUM_STATIC");
    println!("cargo:rerun-if-env-changed=SODIUM_DYNAMIC");

    let linkage = if var("SODIUM_STATIC").is_ok() {
        "static="
    } else if var("SODIUM_DYNAMIC").is_ok() {
        "dylib="
    } else {
        ""
    };

    println!("cargo:rustc-link-search=native={}", lib_dir);
    println!("cargo:rustc-link-lib={}{}", linkage, lib_name());

    println!(
        "cargo:warning=\
         Using unknown libsodium version. This crate is tested against \
         {} and may not be fully compatible with other versions.",
        VERSION
    );

    true
}

#[cfg(all(target_env = "msvc", feature = "vcpkg"))]
fn find_vcpkg() -> bool {
    let lib = match vcpkg::probe_package("libsodium") {
        Ok(lib) => lib,
        Err(err) => {
            eprintln!("Failed to probe Vcpkg tree for libsodium: {}", err);

            return false;
        }
    };

    for lib_dir in &lib.link_paths {
        println!("cargo:lib={}", lib_dir.display());
    }

    for include_dir in &lib.include_paths {
        println!("cargo:include={}", include_dir.display());
    }

    println!(
        "cargo:warning=\
         Using unknown libsodium version. This crate is tested against \
         {} and may not be fully compatible with other versions.",
        VERSION
    );

    true
}

#[cfg(not(all(target_env = "msvc", feature = "vcpkg")))]
fn find_vcpkg() -> bool {
    false
}

#[cfg(feature = "pkg-config")]
fn find_pkg_config() -> bool {
    let lib = match pkg_config::Config::new().probe("libsodium") {
        Ok(lib) => lib,
        Err(err) => {
            eprintln!("Failed to probe libsodium using pkg-config: {}", err);
            return false;
        }
    };

    for lib_dir in &lib.link_paths {
        println!("cargo:lib={}", lib_dir.display());
    }

    for include_dir in &lib.include_paths {
        println!("cargo:include={}", include_dir.display());
    }

    if lib.version != VERSION {
        println!(
            "cargo:warning=\
             Using libsodium version {}. This crate is tested against \
             {} and may not be fully compatible with {}.",
            lib.version, VERSION, lib.version
        );
    }

    true
}

#[cfg(not(feature = "pkg-config"))]
fn find_pkg_config() -> bool {
    false
}

fn link_prebuilt() -> bool {
    let target = var("TARGET").unwrap();
    let profile = var("PROFILE").unwrap();

    let lib_dir = match (target.as_str(), profile.as_str()) {
        ("x86_64-pc-windows-msvc", "release") => "msvc/x64/Release/v140",
        ("x86_64-pc-windows-msvc", _) => "msvc/x64/Debug/v140",
        ("i686-pc-windows-msvc", "release") => "msvc/Win32/Release/v140",
        ("i686-pc-windows-msvc", _) => "msvc/Win32/Debug/v140",
        ("x86_64-pc-windows-gnu", _) => "mingw/win64",
        ("i686-pc-windows-gnu", _) => "mingw/win32",
        _ => return false,
    };

    let manifest_dir: PathBuf = var("CARGO_MANIFEST_DIR").unwrap().into();
    let include_dir = manifest_dir.join("libsodium/src/libsodium/include");
    let lib_dir = manifest_dir.join(lib_dir);

    if var("SODIUM_DYNAMIC").is_ok() {
        println!("cargo:warning=`SODIUM_DYNAMIC` has no effect when linking prebuilt libraries.");
    }

    println!("cargo:rustc-link-search=native={}", lib_dir.display());
    println!("cargo:rustc-link-lib=static={}", lib_name());

    println!("cargo:include={}", include_dir.display());
    println!("cargo:lib={}", lib_dir.display());

    true
}

#[cfg(all(not(target_env = "msvc"), feature = "cc"))]
fn build_from_source() -> bool {
    use std::env::temp_dir;
    use std::fs::{canonicalize, create_dir_all};
    use std::process::Command;
    use std::str::from_utf8;

    fn check_status(mut cmd: Command) {
        match cmd.status() {
            Ok(status) if status.success() => (),
            Ok(status) => panic!("Failed to run `{:?}`: {}", cmd, status),
            Err(error) => panic!("Failed to run `{:?}`: {}", cmd, error),
        }
    }

    let target = var("TARGET").unwrap();
    let profile = var("PROFILE").unwrap();
    let host = var("HOST").unwrap();

    if target != host {
        println!("See https://github.com/sodiumoxide/sodiumoxide#cross-compiling for more information on cross-compiling.");
    }

    let mut out_dir: PathBuf = var("OUT_DIR").unwrap().into();

    // Avoid issues with paths containing spaces by falling back to using a tempfile.
    // See https://github.com/jedisct1/libsodium/issues/207
    if out_dir.to_str().unwrap().contains(' ') {
        out_dir = temp_dir()
            .join("libsodium-sys")
            .join(&target)
            .join(&profile);

        println!(
            "cargo:warning=The path to the default build directory contains spaces and hence \
             can't be used to build libsodium. Falling back to use {}. If running `cargo \
             clean`, ensure you also delete that directory.",
            out_dir.display()
        );
    }

    let install_dir = out_dir.join("installed");
    create_dir_all(&install_dir).unwrap();

    let source_dir = out_dir.join("source");
    create_dir_all(&source_dir).unwrap();

    let mut copy_cmd = Command::new("cp");
    copy_cmd.arg("-r").arg("libsodium").arg(&source_dir);
    check_status(copy_cmd);

    let source_dir = source_dir.join("libsodium");

    // Decide on CC, CFLAGS environment variables and --host argument
    let build_compiler = cc::Build::new().get_compiler();
    let cc_env = build_compiler.path().to_str().unwrap().to_string();
    let mut cflags_env = build_compiler.cflags_env().into_string().unwrap();
    let mut host_arg = format!("--host={}", target);

    if target.contains("-ios") {
        // Determine Xcode directory path
        let xcode_dir: PathBuf = match Command::new("xcode-select").arg("-p").output() {
            Ok(ref output) if output.status.success() => {
                from_utf8(&output.stdout).unwrap().trim().to_string().into()
            }
            Ok(output) => panic!("Failed to run `xcode-select -p`: {}", output.status),
            Err(error) => panic!("Failed to run `xcode-select -p`: {}", error),
        };

        // Determine SDK directory paths
        let sdk_dir_simulator =
            xcode_dir.join("Platforms/iPhoneSimulator.platform/Developer/SDKs/iPhoneSimulator.sdk");
        let sdk_dir_ios = xcode_dir.join("Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS.sdk");

        // Roughly based on `dist-build/ios.sh` in the libsodium sources
        const IOS_SIMULATOR_VERSION_MIN: &str = "6.0.0";
        const IOS_VERSION_MIN: &str = "6.0.0";

        match target.as_str() {
            "aarch64-apple-ios" => {
                cflags_env += " -arch arm64";
                cflags_env += &format!(" -isysroot {}", sdk_dir_ios.display());
                cflags_env += &format!(" -mios-version-min={}", IOS_VERSION_MIN);
                cflags_env += " -fembed-bitcode";
                host_arg = "--host=arm-apple-darwin10".to_string();
            }
            "armv7-apple-ios" => {
                cflags_env += " -arch armv7";
                cflags_env += &format!(" -isysroot {}", sdk_dir_ios.display());
                cflags_env += &format!(" -mios-version-min={}", IOS_VERSION_MIN);
                cflags_env += " -mthumb";
                host_arg = "--host=arm-apple-darwin10".to_string();
            }
            "armv7s-apple-ios" => {
                cflags_env += " -arch armv7s";
                cflags_env += &format!(" -isysroot {}", sdk_dir_ios.display());
                cflags_env += &format!(" -mios-version-min={}", IOS_VERSION_MIN);
                cflags_env += " -mthumb";
                host_arg = "--host=arm-apple-darwin10".to_string();
            }
            "i386-apple-ios" => {
                cflags_env += " -arch i386";
                cflags_env += &format!(" -isysroot {}", sdk_dir_simulator.display());
                cflags_env +=
                    &format!(" -mios-simulator-version-min={}", IOS_SIMULATOR_VERSION_MIN);
                host_arg = "--host=i686-apple-darwin10".to_string();
            }
            "x86_64-apple-ios" => {
                cflags_env += " -arch x86_64";
                cflags_env += &format!(" -isysroot {}", sdk_dir_simulator.display());
                cflags_env +=
                    &format!(" -mios-simulator-version-min={}", IOS_SIMULATOR_VERSION_MIN);
                host_arg = "--host=x86_64-apple-darwin10".to_string();
            }
            target => panic!("Unknown iOS build target: {}", target),
        }
    } else if target.contains("i686") {
        cflags_env += " -m32 -maes -march=i686";
    }

    // Run `./configure`
    let mut configure_cmd = Command::new(canonicalize(source_dir.join("configure")).expect("Failed to find configure script! Did you clone the submodule at `libsodium-sys/libsodium`?"));

    configure_cmd
        .current_dir(&source_dir)
        .env("CC", cc_env)
        .env("CFLAGS", cflags_env)
        .arg(&host_arg)
        .arg(&format!("--prefix={}", install_dir.display()))
        .arg(&format!("--libdir={}/lib", install_dir.display()))
        .arg("--disable-shared")
        .arg("--disable-dependency-tracking");

    // Disable PIE if requested
    println!("cargo:rerun-if-env-changed=SODIUM_DISABLE_PIE");

    if var("SODIUM_DISABLE_PIE").is_ok() {
        configure_cmd.arg("--disable-pie");
    }

    check_status(configure_cmd);

    // Run `make install`
    let mut make_cmd = Command::new("make");

    make_cmd
        .current_dir(&source_dir)
        .env("V", "1")
        .arg(&format!("-j{}", var("NUM_JOBS").unwrap()))
        .arg("install");

    check_status(make_cmd);

    let include_dir = source_dir.join("src/libsodium/include");
    let lib_dir = install_dir.join("lib");

    if var("SODIUM_DYNAMIC").is_ok() {
        println!(
            "cargo:warning=`SODIUM_DYNAMIC` has no effect when building libsodium from source."
        );
    }

    println!("cargo:rustc-link-search=native={}", lib_dir.display());
    println!("cargo:rustc-link-lib=static=sodium");

    println!("cargo:include={}", include_dir.display());
    println!("cargo:lib={}", lib_dir.display());

    true
}

#[cfg(any(target_env = "msvc", not(feature = "cc")))]
fn build_from_source() -> bool {
    false
}
