# mole-p256

Shared P-256 backend and derivation code for the [MOLE](https://github.com/Moderation-of-unLinkable-Endorsements) protocols. The code is extracted from [EC-IHAT](https://github.com/Moderation-of-unLinkable-Endorsements/ihat-rs) and [EC-ACT](https://github.com/Moderation-of-unLinkable-Endorsements/act-rs), so neither protocol needs to depend on the other to share cryptographic implementations.

The `Backend` trait provides P-256 scalar and point arithmetic, SHA-256, hash-to-curve, and randomness. Chris Patton's [hash extension](https://github.com/Moderation-of-unLinkable-Endorsements/ihat-rs/pull/19) is implemented as a blanket `BackendHashExt` trait with an **explicit protocol context** for domain separation. The library does not contain protocol algorithms, ACT's fixed-base tables, or ACT's SHAKE128 transcript implementation.

## Backends

- `rustcrypto` (default): `p256`, `sha2`, and `getrandom`.
- `boringssl`: the BoringSSL implementation through `bssl-sys`, for Chromium integrations.
- `std` enables the standard-library facilities and P-256 precomputed generator tables; `wasm_js` enables the JavaScript randomness source where supported.
- `no_std` with `alloc` is supported when a backend is selected.

## Development

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo check --no-default-features --features rustcrypto
cargo doc --no-deps
```

To build the optional BoringSSL backend, install git, clang, cmake, ninja, and `bindgen-cli`, then:

```sh
scripts/build-boringssl.sh
export BORINGSSL_BUILD_DIR="$PWD/boringssl/build"
cargo test --no-default-features --features boringssl --config boringssl/cargo-config.toml
cargo test --features rustcrypto,boringssl --config boringssl/cargo-config.toml
```

The script pins the compatible BoringSSL revision and patches `bssl-sys` to the locally built bindings.

## Security notes

Scalar and point encodings preserve the original 32-byte canonical scalar and 33-byte compressed SEC1 point representation, without an identity encoding. Point addition through BoringSSL's `EC_POINT_add` has exceptional branches for equal and opposite operands. Constant-time requirements therefore depend on how protocol callers use these operations; `PartialEq` should not be substituted for `Point::ct_eq` when secrecy requires a constant-time comparison.

This is an initial extraction. EC-IHAT and EC-ACT will need separate consumer migration PRs and unchanged test vectors before their old shared code can be removed.
