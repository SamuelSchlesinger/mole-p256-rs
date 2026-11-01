//! Regression tests for the shared-backend extraction review.

use crate::backend::{Backend, Point, Scalar};
use crate::hash::{BackendHashExt, Error, XmdPrefix};

include!("derivation_vectors.rs");

fn reference_derivations<B: Backend>() {
    let seed: [u8; 48] = core::array::from_fn(|i| i as u8);
    let secret: [u8; 32] = core::array::from_fn(|i| i as u8);
    for vector in &DERIVATION_VECTORS {
        assert_eq!(
            hex::encode(B::hash_to_scalar(vector.context, &[b"example"]).to_bytes()),
            vector.scalar
        );
        let scalars = B::derive_scalars(vector.context, &seed, b"test", 3).unwrap();
        for (actual, expected) in scalars.iter().zip(vector.scalars) {
            assert_eq!(hex::encode(actual.to_bytes()), expected);
        }
        let nonces = B::derive_nonces(
            vector.context,
            &secret,
            b"nonce",
            &[b"review-", b"fixture"],
            &seed,
            3,
        )
        .unwrap();
        for (actual, expected) in nonces.iter().zip(vector.nonces) {
            assert_eq!(hex::encode(actual.to_bytes()), expected);
        }
        assert_eq!(
            hex::encode(B::derive_key_scalar(vector.context, &seed, b"GenerateKeyPair").unwrap().to_bytes()),
            vector.key
        );
    }
    assert_eq!(hex::encode(B::reduce_be_48(&[0xff; 48]).to_bytes()), REDUCE_MAX_VECTOR);
    assert!(bool::from(B::reduce_be_48(&[0; 48]).is_zero()));
}

fn xmd_multiblock_and_long_dst<B: Backend>() {
    const DST: &[u8] = b"QUUX-V01-CS02-with-expander-SHA256-128";
    // RFC 9380 Appendix K.1: four blocks, exercising b_2, b_3, and b_4.
    const EXPECTED: &str = concat!(
        "af84c27ccfd45d41914fdff5df25293e221afc53d8ad2ac06d5e3e29485dadbee0",
        "d121587713a3e0dd4d5e69e93eb7cd4f5df4cd103e188cf60cb02edc3edf18e",
        "da8576c412b18ffb658e3dd6ec849469b979d444cf7b26911a08e63cf31f9d",
        "cc541708d3491184472c2c29bb749d4286b004ceb5ee6b9a7fa5b646c993f0ced"
    );
    let mut output = [0u8; 128];
    XmdPrefix::<B::Sha256>::new(&[]).expand_into(&[b""], &[DST], &mut output);
    assert_eq!(hex::encode(output), EXPECTED);

    let long_dst = [b'x'; 512];
    let mut long_output = [0u8; 48];
    XmdPrefix::<B::Sha256>::new(&[b"a"]).expand_into(
        &[b"bc"],
        &[&long_dst[..200], &long_dst[200..]],
        &mut long_output,
    );
    assert_eq!(hex::encode(long_output), OVERSIZE_DST_VECTOR);

    let mut maximum = [0u8; 8160];
    assert!(XmdPrefix::<B::Sha256>::new(&[])
        .try_expand_into(&[], &[DST], &mut maximum)
        .is_ok());
    let mut too_long = [0x55u8; 8161];
    assert_eq!(
        XmdPrefix::<B::Sha256>::new(&[]).try_expand_into(&[], &[DST], &mut too_long),
        Err(Error::InvalidInput)
    );
    assert_eq!(too_long, [0x55; 8161]);
}

fn long_contexts_do_not_panic<B: Backend>() {
    let seed = [42u8; 48];
    for length in [241, 242, 243, 255, 256, 512] {
        let context = alloc::vec![b'x'; length];
        let _ = B::hash_to_scalar(&context, &[b"test"]);
        assert!(B::derive_scalars(&context, &seed, b"test", 2).is_ok());
        assert!(B::derive_nonces(&context, b"secret", b"proof", &[b"instance"], &seed, 2).is_ok());
        assert!(B::derive_key_scalar(&context, &seed, b"test").is_ok());
        assert!(B::expand_scalars(&context, &[42u8; 32], 2).is_ok());
    }
}

fn point_selection<B: Backend>() {
    let generator = B::Point::generator();
    let table = [generator.clone(), generator.double(), generator.neg()];
    for (index, expected) in table.iter().enumerate() {
        let mut visited = 0;
        let selected = B::Point::ct_select(
            table.iter().inspect(|_| visited += 1),
            index,
        );
        assert_eq!(visited, table.len());
        assert_eq!(selected.into_option().unwrap(), *expected);
    }
    assert!(bool::from(B::Point::ct_select(table.iter(), table.len()).is_none()));
    assert!(bool::from(B::Point::ct_select(table.iter(), usize::MAX).is_none()));
    assert!(bool::from(B::Point::ct_select(core::iter::empty(), 0).is_none()));
    let invalid = [generator, B::Point::identity()];
    assert!(bool::from(B::Point::ct_select(invalid.iter(), 0).is_none()));
    assert!(bool::from(B::Point::ct_select(invalid.iter(), 1).is_none()));
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct SeedBackend<B>(core::marker::PhantomData<B>);

impl<B: Backend> Backend for SeedBackend<B> {
    type Scalar = B::Scalar;
    type Point = B::Point;
    type Sha256 = B::Sha256;

    fn hash_to_curve(msg: &[&[u8]], dst: &[&[u8]]) -> Option<Self::Point> {
        B::hash_to_curve(msg, dst)
    }

    fn random_bytes(buf: &mut [u8]) {
        buf.fill(0x42);
    }
}

fn seed_generation_uses_backend<B: Backend>() {
    let seed = SeedBackend::<B>::generate_seed();
    assert_eq!(&*seed, &[0x42; crate::SEED_LENGTH]);
}

macro_rules! review_tests {
    ($module:ident, $backend:path) => {
        mod $module {
            type B = $backend;
            #[test]
            fn reference_derivations() { super::reference_derivations::<B>(); }
            #[test]
            fn xmd_multiblock_and_long_dst() { super::xmd_multiblock_and_long_dst::<B>(); }
            #[test]
            fn long_contexts_do_not_panic() { super::long_contexts_do_not_panic::<B>(); }
            #[test]
            fn point_selection() { super::point_selection::<B>(); }
            #[test]
            fn seed_generation_uses_backend() { super::seed_generation_uses_backend::<B>(); }
            #[test]
            #[should_panic(expected = "XMD length exceeds RFC 9380 limit")]
            fn oversized_output_panics() {
                let mut out = [0u8; 8161];
                crate::hash::XmdPrefix::<<B as crate::Backend>::Sha256>::new(&[])
                    .expand_into(&[], &[b"example"], &mut out);
            }
        }
    };
}

#[cfg(feature = "rustcrypto")]
review_tests!(rustcrypto, crate::backend::rustcrypto::RustCrypto);
#[cfg(feature = "boringssl")]
review_tests!(boringssl, crate::backend::boringssl::BoringSsl);
