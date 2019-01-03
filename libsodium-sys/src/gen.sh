# call this script manually to regen bindings from a new version of libsodium

# a whitelist regex to generate entities
REGEX="(SODIUM|sodium|crypto|randombytes)_.*"

bindgen PATH_TO/libsodium-1.0.16/src/libsodium/include/sodium.h -o sodium_bindings.rs \
  --ctypes-prefix=libc --use-core \
  --generate=functions,types,vars \
  --whitelist-function=$REGEX \
  --whitelist-type=$REGEX \
  --whitelist-var=$REGEX

git apply crypto_generichash_blake2b_state.patch