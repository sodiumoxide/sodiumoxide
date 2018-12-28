#![no_std]
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

extern crate libc;

mod sodium_bindings;
pub use sodium_bindings::*;
