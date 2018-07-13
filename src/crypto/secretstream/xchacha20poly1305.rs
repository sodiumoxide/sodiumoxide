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

    // NOTE: it is impossible to allocate enough memory for `msg` below without
    // overflowing the stack. Further, from all the research I've done and what
    // I know it seems impossible with Rust's type model to mock a call to `len`
    // and none of the mocking libraries seem to privde a workaround. Therefore
    // we cannot test en/decrypting plain/ciphertexts that exceed the ~275GB
    // maximum.
    
    #[test]
    fn decrypt_too_short_ciphertext() {
        let ciphertext: [u8; (ABYTES - 1)] = unsafe { mem::uninitialized() };
        let (_, header, key) = Encryptor::new().unwrap();
        let mut decryptor = Decryptor::init(&header, &key).unwrap();

        // TODO: when custom error types are introduced, this should assert the
        // specific error.
        assert!(decryptor.vdecrypt(&ciphertext, None).is_err());
    }

    #[test]
    fn test_push_pull() {
        let mut msg1 = [0; 128];
        let mut msg2  = [0; 34];
        let mut msg3 = [0; 478];

        randombytes_into(&mut msg1);
        randombytes_into(&mut msg2);
        randombytes_into(&mut msg3);
        
        let (mut encryptor, header, key) = Encryptor::new().unwrap();
        let c1 = encryptor.aencrypt_message(&msg1, None).unwrap();
        let c2 = encryptor.aencrypt_push(&msg2, None).unwrap();
        let c3 = encryptor.aencrypt_finalize(&msg3, None).unwrap();

        let mut decryptor = Decryptor::init(&header, &key).unwrap();
        assert!(decryptor.is_not_finalized());

        let (m1, t1) = decryptor.vdecrypt(&c1, None).unwrap();
        assert_eq!(t1, Tag::Message);
        assert_eq!(msg1[..], m1[..]);
        assert!(decryptor.is_not_finalized());

        let (m2, t2) = decryptor.vdecrypt(&c2, None).unwrap();
        assert_eq!(t2, Tag::Push);
        assert_eq!(msg2[..], m2[..]);
        assert!(decryptor.is_not_finalized());

        let (m3, t3) = decryptor.vdecrypt(&c3, None).unwrap();
        assert_eq!(t3, Tag::Final);
        assert_eq!(msg3[..], m3[..]);
        assert!(decryptor.is_finalized());
    }

    #[test]
    fn test_push_pull_with_ad() {
        let mut msg1 = [0; 128];
        let mut msg2 = [0; 34];
        let mut msg3 = [0; 478];
        let mut ad1 = [0; 224];
        let mut ad2 = [0; 135];

        randombytes_into(&mut msg1);
        randombytes_into(&mut msg2);
        randombytes_into(&mut msg3);
        randombytes_into(&mut ad1);
        randombytes_into(&mut ad2);
        
        let (mut encryptor, header, key) = Encryptor::new().unwrap();
        let c1 = encryptor.aencrypt_message(&msg1, Some(&ad1)).unwrap();
        let c2 = encryptor.aencrypt_push(&msg2, Some(&ad2)).unwrap();
        let c3 = encryptor.aencrypt_finalize(&msg3, None).unwrap();

        let mut decryptor = Decryptor::init(&header, &key).unwrap();
        assert!(decryptor.is_not_finalized());

        let (m1, t1) = decryptor.vdecrypt(&c1, Some(&ad1)).unwrap();
        assert_eq!(t1, Tag::Message);
        assert_eq!(msg1[..], m1[..]);
        assert!(decryptor.is_not_finalized());

        let (m2, t2) = decryptor.vdecrypt(&c2, Some(&ad2)).unwrap();
        assert_eq!(t2, Tag::Push);
        assert_eq!(msg2[..], m2[..]);
        assert!(decryptor.is_not_finalized());

        let (m3, t3) = decryptor.vdecrypt(&c3, None).unwrap();
        assert_eq!(t3, Tag::Final);
        assert_eq!(msg3[..], m3[..]);
        assert!(decryptor.is_finalized());
    }

    #[test]
    fn test_push_pull_with_rekey() {
        let mut msg1 = [0; 128];
        let mut msg2 = [0; 34];
        let mut msg3 = [0; 478];

        randombytes_into(&mut msg1);
        randombytes_into(&mut msg2);
        randombytes_into(&mut msg3);
        
        let (mut encryptor, header, key) = Encryptor::new().unwrap();
        let c1 = encryptor.aencrypt_message(&msg1, None).unwrap();
        let c2 = encryptor.aencrypt_rekey(&msg2, None).unwrap();
        let c3 = encryptor.aencrypt_finalize(&msg3, None).unwrap();

        let mut decryptor = Decryptor::init(&header, &key).unwrap();
        assert!(decryptor.is_not_finalized());

        let (m1, t1) = decryptor.vdecrypt(&c1, None).unwrap();
        assert_eq!(t1, Tag::Message);
        assert_eq!(msg1[..], m1[..]);
        assert!(decryptor.is_not_finalized());

        let (m2, t2) = decryptor.vdecrypt(&c2, None).unwrap();
        assert_eq!(t2, Tag::Rekey);
        assert_eq!(msg2[..], m2[..]);
        assert!(decryptor.is_not_finalized());

        let (m3, t3) = decryptor.vdecrypt(&c3, None).unwrap();
        assert_eq!(t3, Tag::Final);
        assert_eq!(msg3[..], m3[..]);
        assert!(decryptor.is_finalized());
    }

    #[test]
    fn test_push_pull_with_explicit_rekey() {
        let mut msg1 = [0; 128];
        let mut msg2 = [0; 34];
        let mut msg3 = [0; 478];

        randombytes_into(&mut msg1);
        randombytes_into(&mut msg2);
        randombytes_into(&mut msg3);
        
        let (mut encryptor, header, key) = Encryptor::new().unwrap();
        let c1 = encryptor.aencrypt_message(&msg1, None).unwrap();
        let c2 = encryptor.aencrypt_push(&msg2, None).unwrap();
        encryptor.rekey();
        let c3 = encryptor.aencrypt_finalize(&msg3, None).unwrap();

        let mut decryptor = Decryptor::init(&header, &key).unwrap();
        assert!(decryptor.is_not_finalized());

        let (m1, t1) = decryptor.vdecrypt(&c1, None).unwrap();
        assert_eq!(t1, Tag::Message);
        assert_eq!(msg1[..], m1[..]);
        assert!(decryptor.is_not_finalized());

        let (m2, t2) = decryptor.vdecrypt(&c2, None).unwrap();
        assert_eq!(t2, Tag::Push);
        assert_eq!(msg2[..], m2[..]);
        assert!(decryptor.is_not_finalized());

        decryptor.rekey().unwrap();
        assert!(decryptor.is_not_finalized());

        let (m3, t3) = decryptor.vdecrypt(&c3, None).unwrap();
        assert_eq!(t3, Tag::Final);
        assert_eq!(msg3[..], m3[..]);
        assert!(decryptor.is_finalized());
    }

    #[test]
    fn cannot_vdecrypt_after_finalization() {
        let m = [0; 128];
        let (encryptor, header, key) = Encryptor::new().unwrap();
        let c = encryptor.aencrypt_finalize(&m, None).unwrap();
        let mut decryptor = Decryptor::init(&header, &key).unwrap();
        decryptor.vdecrypt(&c, None).unwrap();
        // TODO: check specific `Err(())` when implemented (#221).
        assert!(decryptor.vdecrypt(&c, None).is_err());
    }

    #[test]
    fn cannot_rekey_after_finalization() {
        let m = [0; 128];
        let (encryptor, header, key) = Encryptor::new().unwrap();
        let c = encryptor.aencrypt_finalize(&m, None).unwrap();
        let mut decryptor = Decryptor::init(&header, &key).unwrap();
        decryptor.vdecrypt(&c, None).unwrap();
        // TODO: check specific `Err(())` when implemented (#221).
        assert!(decryptor.rekey().is_err());
    }
    
}
