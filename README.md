sodiumoxide
===========

[![Build Status](https://travis-ci.org/sodiumoxide/sodiumoxide.svg?branch=master)](https://travis-ci.org/sodiumoxide/sodiumoxide)
[![Latest Version](https://img.shields.io/crates/v/sodiumoxide.svg)](https://crates.io/crates/sodiumoxide) 
[![Join the chat at https://gitter.im/rust-sodiumoxide/Lobby](https://badges.gitter.im/rust-sodiumoxide/Lobby.svg)](https://gitter.im/rust-sodiumoxide/Lobby?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)

> [NaCl](http://nacl.cr.yp.to) (pronounced "salt") is a new easy-to-use high-speed software library for network communication, encryption, decryption, signatures, etc. NaCl's goal is to provide all of the core operations needed to build higher-level cryptographic tools.
> Of course, other libraries already exist for these core operations. NaCl advances the state of the art by improving security, by improving usability, and by improving speed.

> [Sodium](https://github.com/jedisct1/libsodium) is a portable, cross-compilable, installable, packageable fork of NaCl (based on the latest released upstream version nacl-20110221), with a compatible API.

This package aims to provide a type-safe and efficient Rust binding that's just
as easy to use.

Dependencies
------------

[Clang](https://clang.llvm.org/) >= 3.9

[Libsodium](https://github.com/jedisct1/libsodium) 1.0.16 ([installation](https://download.libsodium.org/doc/installation))

pkg-config (OSX: `brew install pkg-config`)

Building
--------
    cargo build

Testing
-------
    cargo test

Documentation
-------------
    cargo doc

Documentation will be generated in target/doc/...

Most documentation is taken from NaCl, with minor modification where the API
differs between the C and Rust versions.

Documentation for the latest build can be found at
[gh-pages](https://sodiumoxide.github.io/sodiumoxide).

Optional features
-----------------

Several [optional features](http://doc.crates.io/manifest.html#usage-in-end-products) are available:

* `std` (default: **enabled**). When this feature is disabled,
  sodiumoxide builds using `#![no_std]`. Some functionality may be lost.
  Requires a nightly build of Rust.

* `serde` (default: **enabled**). Allows serialization and deserialization of
  keys, authentication tags, etc. using the
  [serde library](https://crates.io/crates/serde).

* `benchmarks` (default: **disabled**). Compile benchmark tests. Requires a
  nightly build of Rust.

Examples
--------
TBD

Platform Compatibiility 
------------------------
Sodiumoxide has been tested on: 

 Linux -  Yes

 Windows - In Progress 

 Mac OS - `

 IOS -

 Android -


Join in
=======
File bugs in the issue tracker

Master git repository

    git clone https://github.com/sodiumoxide/sodiumoxide.git

License
-------

Licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

### Contribution

Go through the [CONTRIBUTING.md](https://github.com/sodiumoxide/sodiumoxide/blob/master/CONTRIBUTING.md) document to know more about how to contribute to this project.

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0
license, shall be dual licensed as above, without any additional terms or
conditions.

### Code of Conduct

We believe in creating an enabling community for developers and have laid out a general [code of conduct](https://github.com/sodiumoxide/sodiumoxide/blob/master/CODE_OF_CONDUCT.md). Please read and adopt it to help us achieve and maintain the desired community standards.
