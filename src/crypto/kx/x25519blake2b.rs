//! `x25519blake2b` is the current default key exchange scheme of `libsodium`.

#[cfg(not(feature = "std"))]
use prelude::*;

use ffi;

/// Number of bytes in a `PublicKey`.
pub const PUBLICKEYBYTES: usize = ffi::crypto_kx_PUBLICKEYBYTES;

/// Number of bytes in a `SecretKey`.
pub const SECRETKEYBYTES: usize = ffi::crypto_kx_SECRETKEYBYTES;

/// NUmber of bytes in a `Seed`.
pub const SEEDBYTES: usize = ffi::crypto_kx_SEEDBYTES;

/// Number of bytes in a `SessionKey`.
pub const SESSIONKEYBYTES: usize = ffi::crypto_kx_SESSIONKEYBYTES;

new_type! {
    /// `PublicKey` for key exchanges.
    public PublicKey(PUBLICKEYBYTES);
}

new_type! {
    /// `SecretKey` for key exchanges.
    ///
    /// When a `SecretKey` goes out of scope its contents will be zeroed out
    secret SecretKey(SECRETKEYBYTES);
}

new_type! {
    /// `Seed` that can be used for keypair generation
    ///
    /// The `Seed` is used by `keypair_from_seed()` to generate a secret and
    /// public signature key.
    ///
    /// When a `Seed` goes out of scope its content will be zeroed out
    secret Seed(SEEDBYTES);
}

new_type! {
    /// `SessionKey` is returned by `client_session_keys` and `server_session_keys` and is the
    /// exchanged secret between the client and server.
    secret SessionKey(SESSIONKEYBYTES);
}

/// `gen_keypair()` randomly generates a secret key and a corresponding public
/// key.
///
/// THREAD SAFETY: `gen_keypair()` is thread-safe provided that you have
/// called `sodiumoxide::init()` once before using any other function
/// from sodiumoxide.
pub fn gen_keypair() -> (PublicKey, SecretKey) {
    unsafe {
        let mut pk = [0u8; PUBLICKEYBYTES];
        let mut sk = [0u8; SECRETKEYBYTES];
        ffi::crypto_kx_keypair(&mut pk, &mut sk);
        (PublicKey(pk), SecretKey(sk))
    }
}

/// `keypair_from_seed()` computes a secret key and a corresponding public key
/// from a `Seed`.
pub fn keypair_from_seed(&Seed(ref seed): &Seed) -> (PublicKey, SecretKey) {
    unsafe {
        let mut pk = [0u8; PUBLICKEYBYTES];
        let mut sk = [0u8; SECRETKEYBYTES];
        ffi::crypto_kx_seed_keypair(&mut pk, &mut sk, seed);
        (PublicKey(pk), SecretKey(sk))

    }
}

/// `server_session_keys()` computes a pair of shared keys (rx and tx) using the server's public
/// key `server_pk`, the server's secret key `server_sk` and the client's public key `client_pk`.
/// If the client's public key is acceptable, it returns the two shared keys, the first for `rx`
/// and the second for `tx`. Otherwise, it returns `None`.
pub fn server_session_keys(
    &PublicKey(ref server_pk): &PublicKey,
    &SecretKey(ref server_sk): &SecretKey,
    &PublicKey(ref client_pk): &PublicKey,
) -> Result<(SessionKey, SessionKey), ()> {
    unsafe {
        let mut rx = [0u8; SESSIONKEYBYTES];
        let mut tx = [0u8; SESSIONKEYBYTES];
        let r =
            ffi::crypto_kx_server_session_keys(&mut rx, &mut tx, server_pk, server_sk, client_pk);

        if r != 0 {
            Err(())
        } else {
            Ok((SessionKey(rx), SessionKey(tx)))
        }
    }
}

/// `client_session_keys()` computes a pair of shared keys (rx and tx) using the client's public
/// key `client_pk`, the client's secret key `client_sk` and the server's public key `server_pk`.
/// If the server's public key is acceptable, it returns the two shared keys, the first for `rx`
/// and the second for `tx`. Otherwise, it returns `None`.
pub fn client_session_keys(
    &PublicKey(ref client_pk): &PublicKey,
    &SecretKey(ref client_sk): &SecretKey,
    &PublicKey(ref server_pk): &PublicKey,
) -> Result<(SessionKey, SessionKey), ()> {
    unsafe {
        let mut rx = [0u8; SESSIONKEYBYTES];
        let mut tx = [0u8; SESSIONKEYBYTES];
        let r =
            ffi::crypto_kx_client_session_keys(&mut rx, &mut tx, client_pk, client_sk, server_pk);

        if r != 0 {
            Err(())
        } else {
            Ok((SessionKey(rx), SessionKey(tx)))
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_kx() {
        let (client_pk, client_sk) = gen_keypair();
        let (server_pk, server_sk) = gen_keypair();

        assert!(client_pk != server_pk);
        assert!(client_sk != server_sk);

        let (client_rx, client_tx) = client_session_keys(&client_pk, &client_sk, &server_pk)
            .unwrap();
        let (server_rx, server_tx) = server_session_keys(&server_pk, &server_sk, &client_pk)
            .unwrap();

        assert!(client_rx == server_tx);
        assert!(client_tx == server_rx);
    }

    #[test]
    fn test_kx_non_acceptable_keys() {
        let (client_pk, client_sk) = gen_keypair();
        let (server_pk, server_sk) = gen_keypair();

        // non correct public keys
        let fake_client_pk = PublicKey([0u8; PUBLICKEYBYTES]);
        let fake_server_pk = PublicKey([0u8; PUBLICKEYBYTES]);

        assert!(client_session_keys(&client_pk, &client_sk, &fake_server_pk) == Err(()));
        assert!(server_session_keys(&server_pk, &server_sk, &fake_client_pk) == Err(()));
    }
}
