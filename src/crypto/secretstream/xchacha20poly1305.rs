//! `crypto_secretstream_xchacha20poly1305`
use ffi::{crypto_secretstream_xchacha20poly1305_state,
          crypto_secretstream_xchacha20poly1305_init_push,
          crypto_secretstream_xchacha20poly1305_push,
          crypto_secretstream_xchacha20poly1305_init_pull,
          crypto_secretstream_xchacha20poly1305_pull,
          crypto_secretstream_xchacha20poly1305_rekey,
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
