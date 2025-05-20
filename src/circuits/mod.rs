//! # Zero-Knowledge Proof Circuits
//!
//! This module contains implementations of different zero-knowledge proof circuits
//! using the arkworks libraries.
//!
//! ## Circuits
//!
//! * `sum`: A circuit that proves knowledge of two private numbers that sum to a public value
//! * `compare`: A circuit that proves a longer string starts with a shorter string

/// Circuit for string prefix comparison proofs
pub mod compare;
pub mod groth16;
/// Circuit for sum relationship proofs
pub mod sum;
