//! Argon2 summarizes the state of the art in the design of memory-hard functions.
//!
//! It aims at the highest memory filling rate and effective use of multiple
//! computing units, while still providing defense against tradeoff attacks.
//!
//! It prevents ASICs from having a significant advantage over software
//! implementations.
//!
//! Note: libsodium provides a limited version of the Argon2 function. The salt
//! parameter is fixed at 128 bits and the parallelism parameter is fixed to 1.
use ffi;
use randombytes::randombytes_into;
use libc::{c_int, c_ulonglong};

/// Number of bytes in a `Salt`.
pub const SALTBYTES: usize = ffi::crypto_pwhash_argon2id_SALTBYTES;

/// Number of bytes in a `HashedPassword`.
pub const HASHEDPASSWORDBYTES: usize = ffi::crypto_pwhash_argon2id_STRBYTES;

/// All `HashedPasswords` start with this string.
pub const STRPREFIX: &'static str = ffi::crypto_pwhash_argon2id_STRPREFIX;

/// Safe base line for `OpsLimit` for interactive password hashing.
pub const OPSLIMIT_INTERACTIVE: OpsLimit =
    OpsLimit(ffi::crypto_pwhash_argon2id_OPSLIMIT_INTERACTIVE);

/// Safe base line for `MemLimit` for interactive password hashing.
pub const MEMLIMIT_INTERACTIVE: MemLimit =
    MemLimit(ffi::crypto_pwhash_argon2id_MEMLIMIT_INTERACTIVE);

/// `OpsLimit` for moderately sensitive data.
pub const OPSLIMIT_MODERATE: OpsLimit =
    OpsLimit(ffi::crypto_pwhash_argon2id_OPSLIMIT_MODERATE);

/// `MemLimit` for moderately sensitive data.
pub const MEMLIMIT_MODERATE: MemLimit =
    MemLimit(ffi::crypto_pwhash_argon2id_MEMLIMIT_MODERATE);

/// `OpsLimit` for highly sensitive data.
pub const OPSLIMIT_SENSITIVE: OpsLimit =
    OpsLimit(ffi::crypto_pwhash_argon2id_OPSLIMIT_SENSITIVE);

/// `MemLimit` for highly sensitive data.
pub const MEMLIMIT_SENSITIVE: MemLimit =
    MemLimit(ffi::crypto_pwhash_argon2id_MEMLIMIT_SENSITIVE);

/// `OpsLimit` represents the maximum number of computations to perform when
/// using the functions in this module.
///
/// A high `OpsLimit` will make the functions
/// require more CPU cycles
#[derive(Copy, Clone)]
pub struct OpsLimit(pub usize);

/// `MemLimit` represents the maximum amount of RAM that the functions in this
/// module will use, in bytes.
///
/// It is highly recommended to allow the functions to use
/// at least 16 megabytes.
#[derive(Copy, Clone)]
pub struct MemLimit(pub usize);

/// An identifier for the Argon2 algorithm variant to use.
#[derive(Copy, Clone)]
pub enum Variant {
    Argon2i13 = 1,
    Argon2id13 = 2,
}

new_type! {
    /// `Salt` used for password hashing
    public Salt(SALTBYTES);
}

new_type! {
    /// `HashedPassword`is a password verifier generated from a password
    ///
    /// A `HashedPassword` is zero-terminated, includes only ASCII characters and can
    /// be conveniently stored into SQL databases and other data stores. No
    /// additional information has to be stored in order to verify the password.
    public HashedPassword(HASHEDPASSWORDBYTES);
}

/// `gen_salt()` randombly generates a new `Salt` for key derivation
///
/// THREAD SAFETY: `gen_salt()` is thread-safe provided that you have called
/// `sodiumoxide::init()` once before using any other function from sodiumoxide.
pub fn gen_salt() -> Salt {
    let mut salt = Salt([0; SALTBYTES]);
    {
        let Salt(ref mut sb) = salt;
        randombytes_into(sb);
    }
    salt
}

/// The `derive_key()` function derives a key from a password and a `Salt`
///
/// The computed key is stored into key.
///
/// `opslimit` represents a maximum amount of computations to perform. Raising
/// this number will make the function require more CPU cycles to compute a key.
///
/// `memlimit` is the maximum amount of RAM that the function will use, in
/// bytes. It is highly recommended to allow the function to use at least 16
/// megabytes.
///
/// For interactive, online operations, `OPSLIMIT_INTERACTIVE` and
/// `MEMLIMIT_INTERACTIVE` provide a safe base line for these two
/// parameters. However, using higher values may improve security.
///
/// For highly sensitive data, `OPSLIMIT_SENSITIVE` and `MEMLIMIT_SENSITIVE` can
/// be used as an alternative. But with these parameters, deriving a key takes
/// more than 10 seconds on a 2.8 Ghz Core i7 CPU and requires up to 1 gigabyte
/// of dedicated RAM.
///
/// The salt should be unpredictable. `gen_salt()` is the easiest way to create a `Salt`.
///
/// Keep in mind that in order to produce the same key from the same password,
/// the same salt, and the same values for opslimit and memlimit have to be
/// used.
///
/// The function returns `Ok(key)` on success and `Err(())` if the computation didn't
/// complete, usually because the operating system refused to allocate the
/// amount of requested memory.
pub fn derive_key<'a>(key: &'a mut [u8], passwd: &[u8], &Salt(ref sb): &Salt,
                      OpsLimit(opslimit): OpsLimit,
                      MemLimit(memlimit): MemLimit,
                      variant: Variant) -> Result<&'a [u8], ()> {
    if unsafe {
        match variant {
            Variant::Argon2id13 => ffi::crypto_pwhash_argon2id(key.as_mut_ptr(),
                key.len() as c_ulonglong,
                passwd.as_ptr(),
                passwd.len() as c_ulonglong,
                sb,
                opslimit as c_ulonglong,
                memlimit,
                variant as c_int),
            Variant::Argon2i13 => ffi::crypto_pwhash_argon2i(key.as_mut_ptr(),
                key.len() as c_ulonglong,
                passwd.as_ptr(),
                passwd.len() as c_ulonglong,
                sb,
                opslimit as c_ulonglong,
                memlimit,
                variant as c_int),
        }
    } == 0 {
        Ok(key)
    } else {
        Err(())
    }
}

/// The `pwhash()` returns a `HashedPassword` which
/// includes:
///
/// - the result of a memory-hard, CPU-intensive hash function applied to the password
///   `passwd`
/// - the automatically generated salt used for the
///   previous computation
/// - the other parameters required to verify the password: opslimit and memlimit
///
/// `OPSLIMIT_INTERACTIVE` and `MEMLIMIT_INTERACTIVE` are safe baseline
/// values to use for `opslimit` and `memlimit`.
///
/// The function returns `Ok(hashed_password)` on success and `Err(())` if it didn't complete
/// successfully
pub fn pwhash(passwd: &[u8], OpsLimit(opslimit): OpsLimit,
              MemLimit(memlimit): MemLimit) -> Result<HashedPassword, ()> {
    let mut out = HashedPassword([0; HASHEDPASSWORDBYTES]);
    if unsafe {
        let HashedPassword(ref mut str_) = out;
        ffi::crypto_pwhash_argon2id_str(str_,
                                        passwd.as_ptr(),
                                        passwd.len() as c_ulonglong,
                                        opslimit as c_ulonglong,
                                        memlimit)
    } == 0 {
        Ok(out)
    } else {
        Err(())
    }
}

/// `pwhash_verify()` verifies that the password `str_` is a valid password
/// verification string (as generated by `pwhash()`) for `passwd`
///
/// It returns `true` if the verification succeeds, and `false` on error.
pub fn pwhash_verify(&HashedPassword(ref str_): &HashedPassword,
                     passwd: &[u8]) -> bool {
    unsafe {
        ffi::crypto_pwhash_argon2id_str_verify(str_,
                                               passwd.as_ptr(),
                                               passwd.len() as c_ulonglong)
            == 0
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_derive_key() {
        let mut kb = [0u8; 32];
        let salt = Salt(*b"It'll get easier");
        let pw = b"password";
        let key_expected = [0xd6, 0xf0, 0x6b, 0x1d, 0x26, 0x81, 0x86, 0x34,
                            0x15, 0x84, 0xb4, 0x1f, 0xa4, 0x75, 0xf9, 0x46,
                            0x15, 0xac, 0x89, 0x59, 0xfb, 0x07, 0xeb, 0xf0,
                            0xaa, 0xee, 0xe0, 0x9b, 0x74, 0xc6, 0x73, 0xd9];
        let key = derive_key(&mut kb, pw, &salt,
                             OpsLimit(16), MemLimit(8192),
                             Variant::Argon2id13).unwrap();
        assert_eq!(key, key_expected);
    }

    #[test]
    fn test_pwhash_verify() {
        use randombytes::randombytes;
        for i in 0..32usize {
            let pw = randombytes(i);
            let pwh = pwhash(&pw, OpsLimit(16), MemLimit(8192)).unwrap();
            assert!(pwhash_verify(&pwh, &pw));
        }
    }

    #[test]
    fn test_pwhash_verify_tamper() {
        use randombytes::randombytes;
        for i in 0..16usize {
            let mut pw = randombytes(i);
            let pwh = pwhash(&pw, OpsLimit(16), MemLimit(8192)).unwrap();
            for j in 0..pw.len() {
                pw[j] ^= 0x20;
                assert!(!pwhash_verify(&pwh, &pw));
                pw[j] ^= 0x20;
            }
        }
    }

    #[cfg(feature = "serde")]
    #[test]
    fn test_serialisation() {
        use randombytes::randombytes;
        use test_utils::round_trip;
        for i in 0..32usize {
            let pw = randombytes(i);
            let pwh = pwhash(&pw, OPSLIMIT_INTERACTIVE, MEMLIMIT_INTERACTIVE).unwrap();
            let salt = gen_salt();
            round_trip(pwh);
            round_trip(salt);
        }
    }
}
