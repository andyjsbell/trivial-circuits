//! # Trivial Circuits
//!
//! A library implementing simple zero-knowledge proof circuits using the [arkworks](https://arkworks.rs/) libraries.
//!
//! ## Overview
//!
//! This library provides implementations of two basic circuits:
//!
//! * **Sum Circuit** - Proves knowledge of two private numbers that sum to a public value
//! * **Compare Circuit** - Proves that a longer string starts with a specified shorter string
//!
//! These circuits demonstrate the core concepts of zero-knowledge proofs and constraint systems
//! using the [Groth16](https://eprint.iacr.org/2016/260) proving system on the BN254 elliptic curve.
//!
//! ## Example
//!
//! ```rust
//! // Sum Circuit example
//! use trivial_circuits::circuits::sum::SumCircuit;
//! use ark_bn254::Fr;
//!
//! let circuit = SumCircuit::<Fr> {
//!     a: Some(10.into()),
//!     b: Some(32.into()),
//!     c: Some(42.into()),
//! };
//!
//! // Use circuit to generate and verify proofs...
//! ```

/// Circuits module contains implementations of different zero-knowledge proof circuits
pub mod circuits;
