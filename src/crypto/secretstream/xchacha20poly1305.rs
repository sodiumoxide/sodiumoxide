//! `crypto_stream_chacha20` (Chacha20)
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
        
        let (mut push_state, header) = init_push(&key);
        let c1 = push_state.push(&msg1, None, TAG_MESSAGE);
        let c2 = push_state.push(&msg2, None, TAG_PUSH);
        let c3 = push_state.push(&msg3, None, TAG_FINAL);

        let mut pull_state = init_pull(&header, &key).unwrap();
        let (m1, t1) = pull_state.pull(&c1, None).unwrap();
        let (m2, t2) = pull_state.pull(&c2, None).unwrap();
        let (m3, t3) = pull_state.pull(&c3, None).unwrap();
        
        assert_eq!(t1, TAG_MESSAGE);
        assert_eq!(t2, TAG_PUSH);
        assert_eq!(t3, TAG_FINAL);
        assert_eq!(msg1[..], m1[..]);
        assert_eq!(msg2[..], m2[..]);
        assert_eq!(msg3[..], m3[..]);
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
        
        let (mut push_state, header) = init_push(&key);
        let c1 = push_state.push(&msg1, Some(&ad1), TAG_MESSAGE);
        let c2 = push_state.push(&msg2, Some(&ad2), TAG_PUSH);
        let c3 = push_state.push(&msg3, None, TAG_FINAL);

        let mut pull_state = init_pull(&header, &key).unwrap();
        let (m1, t1) = pull_state.pull(&c1, Some(&ad1)).unwrap();
        let (m2, t2) = pull_state.pull(&c2, Some(&ad2)).unwrap();
        let (m3, t3) = pull_state.pull(&c3, None).unwrap();
        
        assert_eq!(t1, TAG_MESSAGE);
        assert_eq!(t2, TAG_PUSH);
        assert_eq!(t3, TAG_FINAL);
        assert_eq!(msg1[..], m1[..]);
        assert_eq!(msg2[..], m2[..]);
        assert_eq!(msg3[..], m3[..]);
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
        
        let (mut push_state, header) = init_push(&key);
        let c1 = push_state.push(&msg1, None, TAG_MESSAGE);
        let c2 = push_state.push(&msg2, None, TAG_REKEY);
        let c3 = push_state.push(&msg3, None, TAG_FINAL);

        let mut pull_state = init_pull(&header, &key).unwrap();
        let (m1, t1) = pull_state.pull(&c1, None).unwrap();
        let (m2, t2) = pull_state.pull(&c2, None).unwrap();
        let (m3, t3) = pull_state.pull(&c3, None).unwrap();
        
        assert_eq!(t1, TAG_MESSAGE);
        assert_eq!(t2, TAG_REKEY);
        assert_eq!(t3, TAG_FINAL);
        assert_eq!(msg1[..], m1[..]);
        assert_eq!(msg2[..], m2[..]);
        assert_eq!(msg3[..], m3[..]);
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
        
        let (mut push_state, header) = init_push(&key);
        let c1 = push_state.push(&msg1, None, TAG_MESSAGE);
        let c2 = push_state.push(&msg2, None, TAG_PUSH);
        push_state.rekey();
        let c3 = push_state.push(&msg3, None, TAG_FINAL);

        let mut pull_state = init_pull(&header, &key).unwrap();
        let (m1, t1) = pull_state.pull(&c1, None).unwrap();
        let (m2, t2) = pull_state.pull(&c2, None).unwrap();
        pull_state.rekey();
        let (m3, t3) = pull_state.pull(&c3, None).unwrap();
        
        assert_eq!(t1, TAG_MESSAGE);
        assert_eq!(t2, TAG_PUSH);
        assert_eq!(t3, TAG_FINAL);
        assert_eq!(msg1[..], m1[..]);
        assert_eq!(msg2[..], m2[..]);
        assert_eq!(msg3[..], m3[..]);
    }
    
}
