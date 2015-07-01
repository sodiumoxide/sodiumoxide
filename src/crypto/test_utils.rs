#![cfg(test)]
extern crate cbor;

use self::cbor::{Encoder, Decoder};
use rustc_serialize::{Decodable, Encodable};

#[doc(hidden)]
// Encodes then decodes `value` using CBOR
pub fn round_trip<T>(value: T) where T: Clone + Decodable + Encodable + Eq {
    let mut encoder = Encoder::from_memory();
    encoder.encode(&[value.clone()]).unwrap();

    let decoded_value: T = Decoder::from_bytes(encoder.as_bytes())
                                   .decode().next().unwrap().unwrap();
    assert!(value == decoded_value);
}
