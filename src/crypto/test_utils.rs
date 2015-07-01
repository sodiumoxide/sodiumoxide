#![cfg(test)]
extern crate cbor;

use self::cbor::{Encoder, Decoder};
use rustc_serialize::{Decodable, Encodable};

use crypto;

pub trait CheckEq {
    fn check(value: Self, decoded_value: Self);
}

impl CheckEq for crypto::box_::curve25519xsalsa20poly1305::PublicKey {
    fn check(value: Self, decoded_value: Self) {
        assert!(value == decoded_value);
    }
}
impl CheckEq for crypto::box_::curve25519xsalsa20poly1305::Nonce {
    fn check(value: Self, decoded_value: Self) {
        assert!(value == decoded_value);
    }
}
impl CheckEq for crypto::sign::ed25519::PublicKey {
    fn check(value: Self, decoded_value: Self) {
        assert!(value == decoded_value);
    }
}
impl CheckEq for crypto::sign::ed25519::Signature {
    fn check(value: Self, decoded_value: Self) {
        assert!(value == decoded_value);
    }
}
impl CheckEq for crypto::auth::hmacsha512::Tag {
    fn check(value: Self, decoded_value: Self) {
        assert!(value == decoded_value);
    }
}
impl CheckEq for crypto::auth::hmacsha512256::Tag {
    fn check(value: Self, decoded_value: Self) {
        assert!(value == decoded_value);
    }
}
impl CheckEq for crypto::auth::hmacsha256::Tag {
    fn check(value: Self, decoded_value: Self) {
        assert!(value == decoded_value);
    }
}
impl CheckEq for crypto::hash::sha512::Digest {
    fn check(value: Self, decoded_value: Self) {
        assert!(value == decoded_value);
    }
}
impl CheckEq for crypto::hash::sha256::Digest {
    fn check(value: Self, decoded_value: Self) {
        assert!(value == decoded_value);
    }
}
impl CheckEq for crypto::secretbox::xsalsa20poly1305::Nonce {
    fn check(value: Self, decoded_value: Self) {
        assert!(value == decoded_value);
    }
}
impl CheckEq for crypto::onetimeauth::poly1305::Tag {
    fn check(value: Self, decoded_value: Self) {
        assert!(value == decoded_value);
    }
}
impl CheckEq for crypto::pwhash::scryptsalsa208sha256::HashedPassword {
    fn check(value: Self, decoded_value: Self) {
        assert!(value == decoded_value);
    }
}
impl CheckEq for crypto::pwhash::scryptsalsa208sha256::Salt {
    fn check(value: Self, decoded_value: Self) {
        assert!(value == decoded_value);
    }
}
impl CheckEq for crypto::stream::xsalsa20::Nonce {
    fn check(value: Self, decoded_value: Self) {
        assert!(value == decoded_value);
    }
}
impl CheckEq for crypto::stream::aes128ctr::Nonce {
    fn check(value: Self, decoded_value: Self) {
        assert!(value == decoded_value);
    }
}
impl CheckEq for crypto::stream::salsa208::Nonce {
    fn check(value: Self, decoded_value: Self) {
        assert!(value == decoded_value);
    }
}
impl CheckEq for crypto::stream::salsa2012::Nonce {
    fn check(value: Self, decoded_value: Self) {
        assert!(value == decoded_value);
    }
}
impl CheckEq for crypto::stream::salsa20::Nonce {
    fn check(value: Self, decoded_value: Self) {
        assert!(value == decoded_value);
    }
}
impl CheckEq for crypto::shorthash::siphash24::Digest {
    fn check(value: Self, decoded_value: Self) {
        assert!(value == decoded_value);
    }
}



impl CheckEq for crypto::auth::hmacsha512::Key {
    fn check(value: Self, decoded_value: Self) {
        assert!(&value[..] == &decoded_value[..]);
    }
}
impl CheckEq for crypto::auth::hmacsha512256::Key {
    fn check(value: Self, decoded_value: Self) {
        assert_eq!(&value[..], &decoded_value[..]);
    }
}
impl CheckEq for crypto::auth::hmacsha256::Key {
    fn check(value: Self, decoded_value: Self) {
        assert_eq!(&value[..], &decoded_value[..]);
    }
}
impl CheckEq for crypto::onetimeauth::poly1305::Key {
    fn check(value: Self, decoded_value: Self) {
        assert_eq!(&value[..], &decoded_value[..]);
    }
}
impl CheckEq for crypto::box_::curve25519xsalsa20poly1305::SecretKey {
    fn check(value: Self, decoded_value: Self) {
        assert_eq!(&value[..], &decoded_value[..]);
    }
}
impl CheckEq for crypto::secretbox::xsalsa20poly1305::Key {
    fn check(value: Self, decoded_value: Self) {
        assert_eq!(&value[..], &decoded_value[..]);
    }
}
impl CheckEq for crypto::shorthash::siphash24::Key {
    fn check(value: Self, decoded_value: Self) {
        assert_eq!(&value[..], &decoded_value[..]);
    }
}
impl CheckEq for crypto::sign::ed25519::SecretKey {
    fn check(value: Self, decoded_value: Self) {
        assert_eq!(&value[..], &decoded_value[..]);
    }
}
impl CheckEq for crypto::stream::xsalsa20::Key {
    fn check(value: Self, decoded_value: Self) {
        assert_eq!(&value[..], &decoded_value[..]);
    }
}
impl CheckEq for crypto::stream::aes128ctr::Key {
    fn check(value: Self, decoded_value: Self) {
        assert_eq!(&value[..], &decoded_value[..]);
    }
}
impl CheckEq for crypto::stream::salsa208::Key {
    fn check(value: Self, decoded_value: Self) {
        assert_eq!(&value[..], &decoded_value[..]);
    }
}
impl CheckEq for crypto::stream::salsa2012::Key {
    fn check(value: Self, decoded_value: Self) {
        assert_eq!(&value[..], &decoded_value[..]);
    }
}
impl CheckEq for crypto::stream::salsa20::Key {
    fn check(value: Self, decoded_value: Self) {
        assert_eq!(&value[..], &decoded_value[..]);
    }
}

#[doc(hidden)]
// Encodes then decodes `value` using CBOR
pub fn round_trip<T>(value: T)
        where T: Clone + Decodable + Encodable + CheckEq {
    let mut encoder = Encoder::from_memory();
    encoder.encode(&[value.clone()]).unwrap();

    let decoded_value: T = Decoder::from_bytes(encoder.as_bytes())
                                   .decode().next().unwrap().unwrap();
    CheckEq::check(value, decoded_value);
}
