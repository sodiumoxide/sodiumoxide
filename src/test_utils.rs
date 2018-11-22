use rmp_serde;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json;

// Encodes then decodes `value` using JSON
pub fn round_trip<T>(value: &T)
where
    T: Serialize + DeserializeOwned + Eq + ::std::fmt::Debug,
{
    let encoded_value = unwrap!(serde_json::to_string(value));
    let decoded_value: T = unwrap!(serde_json::from_str(&encoded_value));
    assert_eq!(*value, decoded_value);

    let mut buf = Vec::new();
    unwrap!(value.serialize(&mut rmp_serde::Serializer::new(&mut buf)));
    let mut de = rmp_serde::Deserializer::new(&buf[..]);
    let decoded_value: T = unwrap!(Deserialize::deserialize(&mut de));
    assert_eq!(*value, decoded_value);
}
