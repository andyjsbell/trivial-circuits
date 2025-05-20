//! # Sum Circuit
//!
//! This module implements a zero-knowledge proof circuit that proves knowledge of two private
//! values that sum to a public value.
//!
//! The circuit takes two private inputs `a` and `b`, and a public output `c`, and proves that
//! `a + b = c` without revealing the values of `a` and `b`.
//!

use ark_ff::PrimeField;
use ark_r1cs_std::{alloc::AllocVar, eq::EqGadget, fields::fp::FpVar};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

/// A circuit that proves knowledge of two values that sum to a public value.
///
/// The prover demonstrates knowledge of private inputs `a` and `b` such that `a + b = c`,
/// where `c` is public. This circuit uses the R1CS (Rank-1 Constraint System) to enforce
/// this relationship.
#[derive(Clone, Default)]
pub struct SumCircuit<F: PrimeField> {
    /// First private value in the sum
    pub a: Option<F>,
    /// Second private value in the sum
    pub b: Option<F>,
    /// Public result of the sum (a + b)
    pub c: Option<F>,
}

impl SumCircuit<ark_bn254::Fr> {
    pub fn new(
        a: Option<ark_bn254::Fr>,
        b: Option<ark_bn254::Fr>,
        c: Option<ark_bn254::Fr>,
    ) -> Self {
        Self { a, b, c }
    }
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
    use super::*;
    use crate::circuits::groth16::{generate_proof, setup, verify_proof};

    /// Test that we can prove and verify that 10 + 32 = 42.
    ///
    /// This test:
    /// 1. Creates a circuit with a = 10, b = 32, c = 42
    /// 2. Generates a proving key and verification key
    /// 3. Creates a proof that a + b = c without revealing a and b
    /// 4. Verifies the proof using the verification key and public input c
    #[test]
    fn prove_verify_sum() {
        let (pk, vk) = setup(SumCircuit::default()).expect("keys created");

        let proof = generate_proof(
            pk,
            SumCircuit::new(Some(10.into()), Some(32.into()), Some(42.into())),
        )
        .expect("proof created");

        let public_input = [42.into()];
        let verified = verify_proof(vk, &public_input, proof).expect("proof is verified");

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
        let (pk, _) = setup(SumCircuit::default()).expect("keys created");
        let _ = generate_proof(
            pk,
            SumCircuit::new(Some(10.into()), Some(31.into()), Some(42.into())),
        );
    }
}
