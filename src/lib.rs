// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Shared P-256 group, hash, and derivation primitives for MOLE protocols.
//!
//! This crate contains no EC-ACT or EC-IHAT protocol logic. Consumers can
//! select RustCrypto or BoringSSL at compile time; each exposes the same
//! [`Backend`] interface. Derived hashing uses explicit protocol contexts
//! and never silently mixes ACT and IHAT domain separation.
//!
//! # Example
//!
//! ```
//! use mole_p256::backend::Point;
//! use mole_p256::DefaultBackend;
//! use mole_p256::hash::BackendHashExt;
//!
//! let scalar = DefaultBackend::hash_to_scalar(b"EC-ACTv1-P256-SHA256", &[b"example"]);
//! let point = DefaultBackend::hash_to_group(b"EC-IHATv1-P256-SHA256", &[b"example"]).unwrap();
//! assert!(point.to_bytes().is_some());
//! let _ = scalar;
//! ```

#![no_std]
#![deny(unsafe_code)]
#![deny(missing_docs)]
#![warn(
    clippy::all,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::missing_safety_doc,
    clippy::undocumented_unsafe_blocks
)]

extern crate alloc;

#[cfg(not(any(feature = "rustcrypto", feature = "boringssl")))]
compile_error!("enable at least one backend feature: `rustcrypto` or `boringssl`");

/// P-256 scalar/group arithmetic, hashing, randomness, and backend implementations.
pub mod backend;
/// RFC 9380 XMD expansion and protocol-domain-separated derivation.
pub mod hash;
/// Randomness abstraction, including the backend's system source.
pub mod random;

pub use backend::Backend;
pub use hash::BackendHashExt;

/// The seed length in bytes used by the two current MOLE P-256 protocols.
pub const SEED_LENGTH: usize = 48;

/// The default backend when BoringSSL is enabled.
#[cfg(feature = "boringssl")]
pub type DefaultBackend = backend::boringssl::BoringSsl;

/// The default backend with only RustCrypto enabled.
#[cfg(all(feature = "rustcrypto", not(feature = "boringssl")))]
pub type DefaultBackend = backend::rustcrypto::RustCrypto;

#[cfg(test)]
mod tests;
