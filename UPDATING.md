# Updating

## Updating libsodium-sys/libsodium submodule

The `libsodium-sys/libsodium` submodule is tracking the latest released version
of `libsodium`. When new version is released, the submodule needs to be updated.

This can be done with following set of commands. This example updates libsodium
submodule into `1.0.14` tag of `libsodium` repository.

1. `git submodule update --init`
2. `cd libsodium-sys/libsodium`
3. `git fetch`
4. `git checkout 1.0.14`
5. `git commit -m "Update to libsodium 1.0.14" libsodium-sys/libsodium/`

Then Git push, etc. as usual.
