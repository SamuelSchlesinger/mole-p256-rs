//! Known-answer tests and backend invariants, run for each enabled backend.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crate::backend::{Backend, POINT_LENGTH, Point, SCALAR_LENGTH, Scalar};
use crate::hash::{BackendHashExt, Error, XmdPrefix};

fn expand_message_xmd_vectors<B: Backend>() {
    // RFC 9380, Appendix K.1, SHA-256.
    const DST: &[u8] = b"QUUX-V01-CS02-with-expander-SHA256-128";
    let cases: [(&[u8], &str); 2] = [
        (
            b"",
            "68a985b87eb6b46952128911f2a4412bbc302a9d759667f87f7a21d803f07235",
        ),
        (
            b"abc",
            "d8ccab23b5985ccea865c6c97b6e5b8350e794e603b4b97902f53a8a0d605615",
        ),
    ];
    for (message, expected) in cases {
        let mut result = [0u8; 32];
        XmdPrefix::<B::Sha256>::new(&[]).expand_into(&[message], &[DST], &mut result);
        assert_eq!(hex::encode(result), expected);
        if !message.is_empty() {
            XmdPrefix::<B::Sha256>::new(&[&message[..1]]).expand_into(
                &[&message[1..]],
                &[&DST[..5], &DST[5..]],
                &mut result,
            );
            assert_eq!(hex::encode(result), expected);
        }
    }
}

fn hash_to_curve_vectors<B: Backend>() {
    // RFC 9380, Appendix J.1.1, P256_XMD:SHA-256_SSWU_RO_.
    const DST: &[u8] = b"QUUX-V01-CS02-with-P256_XMD:SHA-256_SSWU_RO_";
    let cases: [(&[u8], &str, &str); 3] = [
        (
            b"",
            "2c15230b26dbc6fc9a37051158c95b79656e17a1a920b11394ca91c44247d3e4",
            "8a7a74985cc5c776cdfe4b1f19884970453912e9d31528c060be9ab5c43e8415",
        ),
        (
            b"abc",
            "0bb8b87485551aa43ed54f009230450b492fead5f1cc91658775dac4a3388a0f",
            "5c41b3d0731a27a7b14bc0bf0ccded2d8751f83493404c84a88e71ffd424212e",
        ),
        (
            b"abcdef0123456789",
            "65038ac8f2b1def042a5df0b33b1f4eca6bff7cb0f9c6c1526811864e544ed80",
            "cad44d40a656e7aff4002a8de287abc8ae0482b5ae825822bb870d6df9b56ca3",
        ),
    ];
    for (msg, x, y) in cases {
        let point = B::hash_to_curve(&[msg], &[DST]).unwrap();
        let y_bytes = hex::decode(y).unwrap();
        let mut expected = alloc::vec![2 | (y_bytes[31] & 1)];
        expected.extend(hex::decode(x).unwrap());
        assert_eq!(point.to_bytes().unwrap().to_vec(), expected);
    }
}

fn group_and_scalars<B: Backend>() {
    let generator = B::Point::generator();
    assert_eq!(generator.double(), generator.mul(&B::Scalar::from(2)));
    assert_eq!(generator.neg().add(&generator), B::Point::identity());
    assert_eq!(
        hex::encode(generator.to_bytes().unwrap()),
        "036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
    );
    assert!(bool::from(
        B::Point::from_bytes(&[0; POINT_LENGTH]).is_none()
    ));
    assert!(bool::from(
        B::Scalar::from_bytes(&[0xff; SCALAR_LENGTH]).is_none()
    ));
    let mut largest = crate::backend::ORDER;
    largest[SCALAR_LENGTH - 1] -= 1;
    assert!(bool::from(B::Scalar::from_bytes(&largest).is_some()));
    assert!(bool::from(
        B::Scalar::from_bytes(&crate::backend::ORDER).is_none()
    ));
    let x = B::Scalar::from(3);
    assert_eq!(
        (x * x.invert().unwrap()).to_bytes(),
        B::Scalar::from(1).to_bytes()
    );
    let compressed = generator.to_bytes().unwrap();
    assert_eq!(
        B::Point::from_bytes(&compressed).into_option().unwrap(),
        generator
    );
    let gx: [u8; SCALAR_LENGTH] = compressed[1..].try_into().unwrap();
    assert!(bool::from(B::Point::is_x_coordinate(&gx)));
    assert!(!bool::from(B::Point::is_x_coordinate(
        &crate::backend::FIELD_MODULUS
    )));
    let mut wiped = generator.clone();
    wiped.zeroize();
    assert!(bool::from(wiped.is_identity()));
}

fn domain_separation<B: Backend>() {
    const ACT: &[u8] = b"EC-ACTv1-P256-SHA256";
    const IHAT: &[u8] = b"EC-IHATv1-P256-SHA256";
    let seed = [42u8; crate::SEED_LENGTH];
    let a = B::derive_scalars(ACT, &seed, b"test", 3).unwrap();
    let b = B::derive_scalars(IHAT, &seed, b"test", 3).unwrap();
    assert_eq!(a.len(), 3);
    assert_ne!(a[0].to_bytes(), b[0].to_bytes());
    assert_eq!(
        B::derive_scalars(ACT, &seed[..47], b"test", 1).unwrap_err(),
        Error::InvalidInput
    );
    assert_ne!(
        B::hash_to_scalar(ACT, &[b"example"]).to_bytes(),
        B::hash_to_scalar(IHAT, &[b"example"]).to_bytes()
    );
    assert!(!bool::from(
        B::derive_key_scalar(ACT, &seed, b"test").unwrap().is_zero()
    ));
    let nonce_act = B::derive_nonces(ACT, b"secret", b"proof", &[b"instance"], &seed, 2).unwrap();
    let nonce_ihat = B::derive_nonces(IHAT, b"secret", b"proof", &[b"instance"], &seed, 2).unwrap();
    assert_ne!(nonce_act[0].to_bytes(), nonce_ihat[0].to_bytes());
    let repeated = B::derive_nonces(ACT, b"secret", b"proof", &[b"instance"], &seed, 2).unwrap();
    assert_eq!(nonce_act[1].to_bytes(), repeated[1].to_bytes());
}

#[cfg(feature = "rustcrypto")]
mod rustcrypto {
    use super::*;
    type B = crate::backend::rustcrypto::RustCrypto;

    #[test]
    fn xmd() {
        expand_message_xmd_vectors::<B>();
    }
    #[test]
    #[should_panic(expected = "XMD length exceeds RFC 9380 limit")]
    fn oversized_output() {
        let mut out = [0u8; 8161];
        XmdPrefix::<<B as Backend>::Sha256>::new(&[]).expand_into(&[], &[b"example"], &mut out);
    }
    #[test]
    fn hash_to_curve() {
        hash_to_curve_vectors::<B>();
    }
    #[test]
    fn group_and_scalars() {
        super::group_and_scalars::<B>();
    }
    #[test]
    fn domain_separation() {
        super::domain_separation::<B>();
    }
}

#[cfg(feature = "boringssl")]
mod boringssl {
    use super::*;
    type B = crate::backend::boringssl::BoringSsl;

    #[test]
    fn xmd() {
        expand_message_xmd_vectors::<B>();
    }
    #[test]
    fn hash_to_curve() {
        hash_to_curve_vectors::<B>();
    }
    #[test]
    fn group_and_scalars() {
        super::group_and_scalars::<B>();
    }
    #[test]
    fn domain_separation() {
        super::domain_separation::<B>();
    }
}

mod review;
