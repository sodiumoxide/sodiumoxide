# call this script manually to regen bindings from a new version of libsodium

# a whitelist regex to generate entities
REGEX="(SODIUM|sodium|crypto|randombytes)_.*"

bindgen PATH_TO/libsodium-1.0.16/src/libsodium/include/sodium.h -o sodium_bindings.rs \
  --ctypes-prefix=libc --use-core \
  --generate=functions,types,vars \
  --whitelist-function=$REGEX \
  --whitelist-type=$REGEX \
  --whitelist-var=$REGEX

# bindgen fails to compute the alignment in some cases:
# - the alignment of crypto_onetimeauth_poly1305_state should be 16
#   see https://github.com/jedisct1/libsodium/blob/1.0.16/src/libsodium/include/sodium/crypto_onetimeauth_poly1305.h#L19
# - the alignment of crypto_generichash_blake2b_state should be 64
#   see https://github.com/jedisct1/libsodium/blob/1.0.16/src/libsodium/include/sodium/crypto_generichash_blake2b.h#L23
# the patch below fixes this
git apply alignment_fix.patch
