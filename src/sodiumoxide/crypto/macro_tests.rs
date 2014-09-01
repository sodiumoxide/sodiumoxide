use std::rand;
use std::rand::Rng;

#[path="byte_wrapper_macros.rs"]
mod byte_wrapper_macros;

pub static NUMBYTES: uint = 8;

pub struct TestWrapper(pub [u8, ..NUMBYTES]);

byte_wrapper_helpers!(TestWrapper, NUMBYTES)

fn make_rand() -> TestWrapper {
    let mut buff = [0, ..NUMBYTES];
    rand::task_rng().fill_bytes(buff);
    TestWrapper(buff)
}

#[test]
fn test_can_create_from_slice() {
    let b1: &mut [u8] = [1,2,3,4,5,6,7,8];
    let b2: &mut [u8] = [1,2,3,4,5,6,7,8];

    rand::task_rng().fill_bytes(b1);
    rand::task_rng().fill_bytes(b2);

    // Cast away mutability to ensure we can create from an immutable
    // slice.
    let b1: &[u8] = b1;
    let b2: &[u8] = b2;

    let _t1 = TestWrapper::from_slice(b1);
    let _t2 = TestWrapper::from_slice_by_ref(b2);
}

#[test]
fn test_can_borrow_as_slice() {
    let t = make_rand();

    let _s: &[u8] = t.as_slice();
}

#[test]
fn test_equality() {
    let t1 = TestWrapper::from_slice(&[1,2,3,4,5,6,7,8]);
    let t2 = TestWrapper::from_slice(&[1,2,3,4,5,6,7,8]);

    assert!(t1 == t2);

    let t3 = TestWrapper::from_slice(&[1,2,3,4,5,6,7,8]);
    let t4 = TestWrapper::from_slice(&[8,7,6,5,4,3,2,1]);

    assert!(t3 != t4);
}

#[test]
fn test_can_show() {
    let w = make_rand();
    let _s = format!("The value is: {}", w);
}
