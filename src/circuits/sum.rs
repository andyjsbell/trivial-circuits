//! # Sum Circuit
//!
//! This module implements a zero-knowledge proof circuit that proves knowledge of two private
//! values that sum to a public value.
//!
//! The circuit takes two private inputs `a` and `b`, and a public output `c`, and proves that
//! `a + b = c` without revealing the values of `a` and `b`.
//!

use ark_bn254::Bn254;
use ark_ff::PrimeField;
use ark_groth16::{Groth16, Proof, ProvingKey, VerifyingKey};
use ark_r1cs_std::{alloc::AllocVar, eq::EqGadget, fields::fp::FpVar};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_snark::SNARK;
use rand::thread_rng;

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

pub fn setup() -> Result<(ProvingKey<Bn254>, VerifyingKey<Bn254>), String> {
    Groth16::<Bn254>::circuit_specific_setup(
        SumCircuit {
            a: None,
            b: None,
            c: None,
        },
        &mut thread_rng(),
    )
    .map_err(|e| e.to_string())
}

#[derive(Clone, Debug, PartialEq)]
pub struct SumProof(pub Proof<Bn254>);

impl AsRef<Proof<Bn254>> for SumProof {
    fn as_ref(&self) -> &Proof<Bn254> {
        &self.0
    }
}

impl From<Proof<Bn254>> for SumProof {
    fn from(proof: Proof<Bn254>) -> Self {
        SumProof(proof)
    }
}

pub trait TrySerializer {
    fn try_to_bytes(&self) -> Result<Vec<u8>, String>;
}

impl<T> TrySerializer for T
where
    T: CanonicalSerialize,
{
    fn try_to_bytes(&self) -> Result<Vec<u8>, String> {
        let mut bytes = Vec::<u8>::new();
        self.serialize_uncompressed(&mut bytes)
            .map_err(|e| e.to_string())?;
        Ok(bytes)
    }
}

pub fn from_bytes<T: CanonicalDeserialize>(bytes: Vec<u8>) -> Result<T, String> {
    T::deserialize_uncompressed(bytes.as_slice()).map_err(|e| e.to_string())
}

pub fn generate_proof(pk: ProvingKey<Bn254>, a: u32, b: u32, c: u32) -> Result<SumProof, String> {
    Ok(Groth16::<Bn254>::prove(
        &pk,
        SumCircuit {
            a: Some(a.into()),
            b: Some(b.into()),
            c: Some(c.into()),
        },
        &mut thread_rng(),
    )
    .map_err(|e| e.to_string())?
    .into())
}

#[cfg(test)]
mod tests {
    //! Tests for the Sum Circuit.
    //!
    //! These tests demonstrate how to create, prove, and verify a sum circuit.
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

        let (pk, vk) = setup().expect("keys created");
        let proof = generate_proof(pk, a, b, c).expect("proof created");

        let public_input = [c.into()];
        let verified =
            Groth16::<Bn254>::verify(&vk, &public_input, proof.as_ref()).expect("verified");

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
        let b = 31; // Note: 10 + 31 = 41, not 42

        let circuit = SumCircuit {
            a: Some(a.into()),
            b: Some(b.into()),
            c: Some(c.into()),
        };
        let rng = &mut thread_rng();

        let (pk, _) = setup().expect("keys created");
        let _ = Groth16::<Bn254>::prove(&pk, circuit, rng);
    }
}
