macro_rules! aead_module (($encrypt_name:path,
                           $decrypt_name:path,
                           $keybytes:expr,
                           $noncebytes:expr,
                           $macbytes:expr) => (

use randombytes::randombytes_into;
use libc::c_ulonglong;
use std::ptr;

/// Number of bytes in `Key`.
pub const KEYBYTES: usize = $keybytes;

/// Number of bytes in a `Nonce`.
pub const NONCEBYTES: usize = $noncebytes;

/// Number of bytes in the authenticator tag of an encrypted message
/// i.e. the number of bytes by which the ciphertext is larger than the
/// plaintext.
pub const MACBYTES: usize = $macbytes;

new_type! {
    /// `Key` for symmetric authenticated encryption
    ///
    /// When a `Key` goes out of scope its contents
    /// will be zeroed out
    secret Key(KEYBYTES);
}

new_type! {
    /// `Nonce` for symmetric authenticated encryption
    nonce Nonce(NONCEBYTES);
}

/// `gen_key()` randomly generates a secret key
///
/// THREAD SAFETY: `gen_key()` is thread-safe provided that you have
/// called `sodiumoxide::init()` once before using any other function
/// from sodiumoxide.
pub fn gen_key() -> Key {
    let mut key = [0; KEYBYTES];
    randombytes_into(&mut key);
    Key(key)
}

/// `gen_nonce()` randomly generates a nonce
///
/// THREAD SAFETY: `gen_key()` is thread-safe provided that you have
/// called `sodiumoxide::init()` once before using any other function
/// from sodiumoxide.
pub fn gen_nonce() -> Nonce {
    let mut nonce = [0; NONCEBYTES];
    randombytes_into(&mut nonce);
    Nonce(nonce)
}

/// `encrypt()` encrypts the plaintext `m` using a secret
/// key `k`, and a public nonce `n`, and emits a combined
/// byte stream of ciphertext, and an authentication tag
/// authenticating both `m` and the optional additional data in `ad` .
///
/// The public nonce should never be re-used with the same key.
///
/// The encrypted length will be at most m.len() + MACBYTES.
pub fn encrypt(m: &[u8],
               ad: &[u8],
               &Nonce(ref n): &Nonce,
               &Key(ref k): &Key) -> Vec<u8> {

    let mut c : Vec<u8> = Vec::with_capacity(m.len() + MACBYTES);
    let mut clen : c_ulonglong = 0;
    unsafe {
        $encrypt_name(
            c.as_mut_ptr(), &mut clen,
            m.as_ptr(), m.len() as c_ulonglong,
            ad.as_ptr(), ad.len() as c_ulonglong,
            ptr::null_mut(),
            n,
            k);
        assert!(clen as usize <= c.capacity());
        c.set_len(clen as usize);
    }

    c
}

/// `decrypt()` verifies the tagged ciphertext `c` and optional
/// additional data `ad` using a secret key `k`, and a public
/// nonce `n`. It returns the decrypted plaintext if successful,
/// or an `Error` if authentication failed.
///
/// The decrypted length will be at most c.len() - MACBYTES.
pub fn decrypt(c: &[u8],
               ad: &[u8],
               &Nonce(ref n): &Nonce,
               &Key(ref k): &Key) -> Result<Vec<u8>, ()> {
    if c.len() < MACBYTES {
        return Err(());
    }

    let mut m : Vec<u8> = Vec::with_capacity(c.len() - MACBYTES);
    let mut mlen : c_ulonglong = 0;

    let ret = unsafe {
        let ret = $decrypt_name(
            m.as_mut_ptr(), &mut mlen,
            ptr::null_mut(),
            c.as_ptr(), c.len() as c_ulonglong,
            ad.as_ptr(), ad.len() as c_ulonglong,
            n,
            k);
        assert!(mlen as usize <= m.capacity());
        m.set_len(mlen as usize);
        ret
    };

    if ret == 0 {
        Ok(m)
    } else {
        Err(())
    }
}

));


macro_rules! aead_test_fns (($init:expr) => (

#[test]
fn test_encrypt_decrypt() {
    use randombytes::randombytes;

    $init;

    // Vary input length
    for i in 0..256usize {
        let k = gen_key();
        let m = randombytes(i);
        let ad = [5; 10];
        let n = gen_nonce();

        let c = encrypt(&m, &ad, &n, &k);
        let m_new = decrypt(&c, &ad, &n, &k);
        assert_eq!(m, m_new.unwrap());
    }

    // Vary ad length
    for i in 0..256usize {
        let k = gen_key();
        let m = randombytes(10);
        let ad = vec![5; i];
        let n = gen_nonce();
        let c = encrypt(&m, &ad, &n, &k);
        let m_new = decrypt(&c, &ad, &n, &k);
        assert_eq!(m, m_new.unwrap());
    }
}

#[test]
fn test_encrypt_decrypt_tamper() {
    use randombytes::randombytes;

    $init;

    for i in 0..256usize {
        let k = gen_key();
        let m = randombytes(i);
        let ad = [5; 10];
        let n = gen_nonce();
        let c = encrypt(&m, &ad, &n, &k);

        // Mangle ciphertext
        for i in 0..c.len() {
            let mut mangled_c = c.clone();
            mangled_c[i] = mangled_c[i] ^ 255;
            let m_new = decrypt(&mangled_c, &ad, &n, &k);
            assert_eq!(Err(()), m_new);
        }

        // Mangle AD
        for i in 0..ad.len() {
            let mut mangled_ad = ad.clone();
            mangled_ad[i] = mangled_ad[i] ^ 255;
            let m_new = decrypt(&c, &mangled_ad, &n, &k);
            assert_eq!(Err(()), m_new);
        }

        // Truncate ciphertext
        for i in 0..c.len() {
            let mut c_truncated = Vec::new();
            c_truncated.extend_from_slice(&c[0..i]);
            let m_result = decrypt(&c_truncated, &ad, &n, &k);
            assert_eq!(Err(()), m_result);
        }

        // Truncate AD
        for i in 0..ad.len() {
            let mut ad_truncated = Vec::new();
            ad_truncated.extend_from_slice(&ad[0..i]);
            let m_result = decrypt(&c, &ad_truncated, &n, &k);
            assert_eq!(Err(()), m_result);
        }
    }
}

));
