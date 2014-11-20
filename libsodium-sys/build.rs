
fn main () {
  // dummy
  println!("cargo:rustc-flags=-l sodium:static -L ../../libsodium-0.7.0/src/libsodium/.libs/");
}