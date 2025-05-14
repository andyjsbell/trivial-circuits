//! # Sum Circuit
//! 
//! This module implements a zero-knowledge proof circuit that proves knowledge of two private 
//! values that sum to a public value.
//!
//! The circuit takes two private inputs `a` and `b`, and a public output `c`, and proves that
//! `a + b = c` without revealing the values of `a` and `b`.
//!
//! ## Example
//!
//! ```rust
//! use ark_bn254::Fr;
//! use ark_groth16::Groth16;
//! use ark_snark::SNARK;
//! use rand::thread_rng;
//!
//! let circuit = SumCircuit {
//!     a: Some(10.into()),
//!     b: Some(32.into()),
//!     c: Some(42.into()),
//! };
//!
//! // Generate proof that 10 + 32 = 42 without revealing 10 and 32
//! let rng = &mut thread_rng();
//! let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(circuit.clone(), rng).unwrap();
//! let proof = Groth16::<Bn254>::prove(&pk, circuit, rng).expect("proof");
//! ```

use ark_ff::PrimeField;
use ark_r1cs_std::{alloc::AllocVar, eq::EqGadget, fields::fp::FpVar};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

/// A circuit that proves knowledge of two values that sum to a public value.
///
/// The prover demonstrates knowledge of private inputs `a` and `b` such that `a + b = c`,
/// where `c` is public. This circuit uses the R1CS (Rank-1 Constraint System) to enforce
/// this relationship.
#[derive(Clone)]
pub struct SumCircuit<F: PrimeField> {
    /// First private value in the sum
    pub a: Option<F>,
    /// Second private value in the sum
    pub b: Option<F>,
    /// Public result of the sum (a + b)
    pub c: Option<F>,
}

impl<F: PrimeField> ConstraintSynthesizer<F> for SumCircuit<F> {
    /// Generates constraints for the sum circuit.
    ///
    /// This function creates the constraint system that enforces the relationship
    /// `a + b = c`. It allocates variables for the private inputs `a` and `b` 
    /// as witnesses, and the public output `c` as an input.
    ///
    /// # Arguments
    ///
    /// * `cs` - A reference to the constraint system
    ///
    /// # Returns
    ///
    /// * `Result<(), SynthesisError>` - Ok if constraints are successfully generated
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        // Create variables for our private inputs (a and b)
        // c ==> a + b
        let a_var = FpVar::new_witness(cs.clone(), || {
            self.a.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let b_var = FpVar::new_witness(cs.clone(), || {
            self.b.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let c_var = FpVar::new_input(cs.clone(), || {
            self.c.ok_or(SynthesisError::AssignmentMissing)
        })?;

        // Add them together
        let sum = a_var + b_var;
        // Enforce that their sum equals the public output
        sum.enforce_equal(&c_var)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    //! Tests for the Sum Circuit.
    //!
    //! These tests demonstrate how to create, prove, and verify a sum circuit.
    use ark_bn254::Bn254;
    use ark_groth16::Groth16;
    use ark_snark::SNARK;
    use rand::thread_rng;

    use super::*;

    /// Test that we can prove and verify that 10 + 32 = 42.
    ///
    /// This test:
    /// 1. Creates a circuit with a = 10, b = 32, c = 42
    /// 2. Generates a proving key and verification key
    /// 3. Creates a proof that a + b = c without revealing a and b
    /// 4. Verifies the proof using the verification key and public input c
    #[test]
    fn prove_verify_sum() {
        let c = 42;
        let a = 10;
        let b = 32;

        let circuit = SumCircuit {
            a: Some(a.into()),
            b: Some(b.into()),
            c: Some(c.into()),
        };
        let rng = &mut thread_rng();

        let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(circuit.clone(), rng).unwrap();
        let proof = Groth16::<Bn254>::prove(&pk, circuit, rng).expect("proof");
        let public_input = [c.into()];
        let verified = Groth16::<Bn254>::verify(&vk, &public_input, &proof).expect("verified");

        assert!(verified, "this can't be verified");
    }

    /// Test that proof generation fails when the sum constraint is not satisfied.
    ///
    /// This test demonstrates that the prover cannot generate a valid proof when
    /// the values don't satisfy the constraint (a + b = c). Here, 10 + 31 ≠ 42,
    /// so the proof generation should fail.
    #[test]
    #[should_panic(expected = "assertion failed: cs.is_satisfied().unwrap()")]
    fn prove_verify_bad_sum() {
        let c = 42;
        let a = 10;
        let b = 31;  // Note: 10 + 31 = 41, not 42

        let circuit = SumCircuit {
            a: Some(a.into()),
            b: Some(b.into()),
            c: Some(c.into()),
        };
        let rng = &mut thread_rng();

        let (pk, _) = Groth16::<Bn254>::circuit_specific_setup(circuit.clone(), rng).unwrap();
        let _ = Groth16::<Bn254>::prove(&pk, circuit, rng);
    }
}
