extern crate pkg_config;

fn main() {
    pkg_config::find_library("libsodium").unwrap();
}
