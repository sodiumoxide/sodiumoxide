//! `crypto_secretstream_xchacha20poly1305`
use ffi::{crypto_secretstream_xchacha20poly1305_state,
          crypto_secretstream_xchacha20poly1305_init_push,
          crypto_secretstream_xchacha20poly1305_push,
          crypto_secretstream_xchacha20poly1305_init_pull,
          crypto_secretstream_xchacha20poly1305_pull,
          crypto_secretstream_xchacha20poly1305_rekey,
          crypto_secretstream_xchacha20poly1305_messagebytes_max,
          crypto_secretstream_xchacha20poly1305_KEYBYTES,
          crypto_secretstream_xchacha20poly1305_HEADERBYTES,
          crypto_secretstream_xchacha20poly1305_ABYTES,
          crypto_secretstream_xchacha20poly1305_TAG_MESSAGE,
          crypto_secretstream_xchacha20poly1305_TAG_PUSH,
          crypto_secretstream_xchacha20poly1305_TAG_REKEY,
          crypto_secretstream_xchacha20poly1305_TAG_FINAL};

stream_module!(crypto_secretstream_xchacha20poly1305_state,
               crypto_secretstream_xchacha20poly1305_init_push,
               crypto_secretstream_xchacha20poly1305_push,
               crypto_secretstream_xchacha20poly1305_init_pull,
               crypto_secretstream_xchacha20poly1305_pull,
               crypto_secretstream_xchacha20poly1305_rekey,
               crypto_secretstream_xchacha20poly1305_messagebytes_max,
               crypto_secretstream_xchacha20poly1305_KEYBYTES,
               crypto_secretstream_xchacha20poly1305_HEADERBYTES,
               crypto_secretstream_xchacha20poly1305_ABYTES,
               crypto_secretstream_xchacha20poly1305_TAG_MESSAGE,
               crypto_secretstream_xchacha20poly1305_TAG_PUSH,
               crypto_secretstream_xchacha20poly1305_TAG_REKEY,
               crypto_secretstream_xchacha20poly1305_TAG_FINAL);

#[cfg(test)]
mod test {
    use super::*;
    use std::mem;

    // TODO: this const should be in `secretstream_macros`, but it should also
    // be determined by calling the const fn messagebytes_max. This is not
    // possible until `const fn` is stable
    // (https://github.com/rust-lang/rust/issues/24111). Remove attribute if
    // problem with `encrypt_too_long_message` is fixed before we can use
    // `const fn`.
    #[allow(dead_code)]
    const MESSAGEBYTES_MAX: usize = 274877906816;

    // TODO: it is impossible to allocate enough memory for `msg` below without
    // overflowing the stack. Therefore, this test cannot function as written
    // below. However, in writing it the question of how to en/decrypt a
    // plain/ciphertext that cannot fit in memory arose. We must first solve
    // this problem, then we can rewrite this test to make sure this check is
    // working in our code. Since the maximum size is ~275GB, even if we
    // implement a file-like read interface for the encryption and decryption
    // methods, we'll need to create a custom class which lies about its length
    // for testing purposes. We should add an analagous test called
    // `decrypt_message_too_long` as well.
    //
    // #[test]
    // fn encrypt_too_long_message() {
    //     let msg: [u8; (MESSAGEBYTES_MAX + 1)] = unsafe { mem::uninitialized() };
    //     let key = gen_key();
    //     let (mut encryptor, _) = Encryptor::init(&key).unwrap();

    //     assert!(encryptor.message(&msg, None).is_err());
    // }

    #[test]
    fn decrypt_too_short_ciphertext() {
        let ciphertext: [u8; (ABYTES - 1)] = unsafe { mem::uninitialized() };
        let key = gen_key();
        let (_, header) = Encryptor::init(&key).unwrap();
        let mut decryptor = Decryptor::init(&header, &key).unwrap();

        // TODO: when custom error types are introduced, this should assert the
        // specific error.
        assert!(decryptor.decrypt(&ciphertext, None).is_err());
    }

    #[test]
    fn test_push_pull() {
        let key = gen_key();
        
        let mut msg1: [u8; 128] = [0; 128];
        let mut msg2: [u8; 34]  = [0; 34];
        let mut msg3: [u8; 478] = [0; 478];

        randombytes_into(&mut msg1);
        randombytes_into(&mut msg2);
        randombytes_into(&mut msg3);
        
        let (mut encryptor, header) = Encryptor::init(&key).unwrap();
        let c1 = encryptor.message(&msg1, None).unwrap();
        let c2 = encryptor.push(&msg2, None).unwrap();
        let c3 = encryptor.finalize(&msg3, None).unwrap();

        let mut decryptor = Decryptor::init(&header, &key).unwrap();
        assert!(!decryptor.is_finalized());

        let (m1, t1) = decryptor.decrypt(&c1, None).unwrap();
        assert_eq!(t1, Tag::Message);
        assert_eq!(msg1[..], m1[..]);
        assert!(!decryptor.is_finalized());

        let (m2, t2) = decryptor.decrypt(&c2, None).unwrap();
        assert_eq!(t2, Tag::Push);
        assert_eq!(msg2[..], m2[..]);
        assert!(!decryptor.is_finalized());

        let (m3, t3) = decryptor.decrypt(&c3, None).unwrap();
        assert_eq!(t3, Tag::Final);
        assert_eq!(msg3[..], m3[..]);
        assert!(decryptor.is_finalized());
    }

    #[test]
    fn test_push_pull_with_ad() {
        let key = gen_key();
        
        let mut msg1: [u8; 128] = [0; 128];
        let mut msg2: [u8; 34]  = [0; 34];
        let mut msg3: [u8; 478] = [0; 478];
        let mut ad1: [u8; 224] = [0; 224];
        let mut ad2: [u8; 135] = [0; 135];

        randombytes_into(&mut msg1);
        randombytes_into(&mut msg2);
        randombytes_into(&mut msg3);
        randombytes_into(&mut ad1);
        randombytes_into(&mut ad2);
        
        let (mut encryptor, header) = Encryptor::init(&key).unwrap();
        let c1 = encryptor.message(&msg1, Some(&ad1)).unwrap();
        let c2 = encryptor.push(&msg2, Some(&ad2)).unwrap();
        let c3 = encryptor.finalize(&msg3, None).unwrap();

        let mut decryptor = Decryptor::init(&header, &key).unwrap();
        assert!(!decryptor.is_finalized());

        let (m1, t1) = decryptor.decrypt(&c1, Some(&ad1)).unwrap();
        assert_eq!(t1, Tag::Message);
        assert_eq!(msg1[..], m1[..]);
        assert!(!decryptor.is_finalized());

        let (m2, t2) = decryptor.decrypt(&c2, Some(&ad2)).unwrap();
        assert_eq!(t2, Tag::Push);
        assert_eq!(msg2[..], m2[..]);
        assert!(!decryptor.is_finalized());

        let (m3, t3) = decryptor.decrypt(&c3, None).unwrap();
        assert_eq!(t3, Tag::Final);
        assert_eq!(msg3[..], m3[..]);
        assert!(decryptor.is_finalized());
    }

    #[test]
    fn test_push_pull_with_rekey() {
        let key = gen_key();
        
        let mut msg1: [u8; 128] = [0; 128];
        let mut msg2: [u8; 34]  = [0; 34];
        let mut msg3: [u8; 478] = [0; 478];

        randombytes_into(&mut msg1);
        randombytes_into(&mut msg2);
        randombytes_into(&mut msg3);
        
        let (mut encryptor, header) = Encryptor::init(&key).unwrap();
        let c1 = encryptor.message(&msg1, None).unwrap();
        let c2 = encryptor.rekey_message(&msg2, None).unwrap();
        let c3 = encryptor.finalize(&msg3, None).unwrap();

        let mut decryptor = Decryptor::init(&header, &key).unwrap();
        assert!(!decryptor.is_finalized());

        let (m1, t1) = decryptor.decrypt(&c1, None).unwrap();
        assert_eq!(t1, Tag::Message);
        assert_eq!(msg1[..], m1[..]);
        assert!(!decryptor.is_finalized());

        let (m2, t2) = decryptor.decrypt(&c2, None).unwrap();
        assert_eq!(t2, Tag::Rekey);
        assert_eq!(msg2[..], m2[..]);
        assert!(!decryptor.is_finalized());

        let (m3, t3) = decryptor.decrypt(&c3, None).unwrap();
        assert_eq!(t3, Tag::Final);
        assert_eq!(msg3[..], m3[..]);
        assert!(decryptor.is_finalized());
    }

    #[test]
    fn test_push_pull_with_explicit_rekey() {
        let key = gen_key();
        
        let mut msg1: [u8; 128] = [0; 128];
        let mut msg2: [u8; 34]  = [0; 34];
        let mut msg3: [u8; 478] = [0; 478];

        randombytes_into(&mut msg1);
        randombytes_into(&mut msg2);
        randombytes_into(&mut msg3);
        
        let (mut encryptor, header) = Encryptor::init(&key).unwrap();
        let c1 = encryptor.message(&msg1, None).unwrap();
        let c2 = encryptor.push(&msg2, None).unwrap();
        encryptor.rekey();
        let c3 = encryptor.finalize(&msg3, None).unwrap();

        let mut decryptor = Decryptor::init(&header, &key).unwrap();
        assert!(!decryptor.is_finalized());

        let (m1, t1) = decryptor.decrypt(&c1, None).unwrap();
        assert_eq!(t1, Tag::Message);
        assert_eq!(msg1[..], m1[..]);
        assert!(!decryptor.is_finalized());

        let (m2, t2) = decryptor.decrypt(&c2, None).unwrap();
        assert_eq!(t2, Tag::Push);
        assert_eq!(msg2[..], m2[..]);
        assert!(!decryptor.is_finalized());

        decryptor.rekey();
        assert!(!decryptor.is_finalized());

        let (m3, t3) = decryptor.decrypt(&c3, None).unwrap();
        assert_eq!(t3, Tag::Final);
        assert_eq!(msg3[..], m3[..]);
        assert!(decryptor.is_finalized());
    }
    
}
