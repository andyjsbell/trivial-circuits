//! # Compare Circuit
//!
//! This module implements a zero-knowledge proof circuit that proves a longer string
//! starts with a specified shorter string.
//!
//! The circuit takes a public shorter string and a private longer string, and proves that
//! the longer string starts with the shorter string without revealing the entire longer string.
//!

use ark_ff::PrimeField;
use ark_r1cs_std::{alloc::AllocVar, eq::EqGadget, fields::fp::FpVar};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

/// Generate a vector of prime field values for a string
/// Utility type to convert a string to a vector of field elements.
///
/// This struct wraps a vector of field elements, where each element
/// represents a character in the original string.
#[derive(Clone)]
struct PrimeString<F: PrimeField>(Vec<F>);
impl<F: PrimeField> From<&'static str> for PrimeString<F> {
    /// Converts a string to a vector of field elements.
    ///
    /// Each character in the string is converted to its ASCII value and then
    /// to a field element.
    ///
    /// # Arguments
    ///
    /// * `value` - A static string to convert
    fn from(value: &'static str) -> Self {
        Self(
            value
                .as_bytes()
                .iter()
                .map(|c| (*c as u64).into())
                .collect(),
        )
    }
}

impl<F: PrimeField> From<PrimeString<F>> for Vec<F> {
    /// Converts a PrimeString to a standard vector of field elements.
    ///
    /// # Arguments
    ///
    /// * `value` - The PrimeString to convert
    fn from(value: PrimeString<F>) -> Self {
        value.0.clone()
    }
}

/// A circuit that proves a longer string starts with a shorter string.
///
/// This circuit allows a prover to demonstrate that a private longer string
/// starts with a public shorter string, without revealing the entire longer string.
#[derive(Clone, Default)]
pub struct CompareCircuit<F: PrimeField> {
    /// The public shorter string (represented as field elements)
    pub shorter: Option<Vec<F>>,
    /// The private longer string (represented as field elements)
    pub larger: Option<Vec<F>>,
}

impl<F: PrimeField> ConstraintSynthesizer<F> for CompareCircuit<F> {
    /// Generates constraints for the compare circuit.
    ///
    /// This function creates the constraint system that enforces that the longer
    /// string starts with the shorter string. It allocates variables for the
    /// shorter string as public inputs, and for the beginning of the longer string
    /// as witnesses.
    ///
    /// # Arguments
    ///
    /// * `cs` - A reference to the constraint system
    ///
    /// # Returns
    ///
    /// * `Result<(), SynthesisError>` - Ok if constraints are successfully generated
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        let shorter = self.shorter.ok_or(SynthesisError::AssignmentMissing)?;
        let larger = self.larger.ok_or(SynthesisError::AssignmentMissing)?;

        if shorter.len() > larger.len() {
            return Err(SynthesisError::Unsatisfiable);
        }

        // Public
        let shorter_vars = shorter
            .iter()
            .map(|&val| FpVar::new_input(cs.clone(), || Ok(val)))
            .collect::<Result<Vec<_>, _>>()?;

        // Witness
        let larger_vars = larger
            .iter()
            .take(shorter.len())
            .map(|&val| FpVar::new_witness(cs.clone(), || Ok(val)))
            .collect::<Result<Vec<_>, _>>()?;

        for (shorter_var, larger_var) in shorter_vars.iter().zip(larger_vars.iter()) {
            larger_var.enforce_equal(shorter_var)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    //! Tests for the Compare Circuit.
    //!
    //! These tests demonstrate how to create, prove, and verify a compare circuit.
    use super::{CompareCircuit, PrimeString};
    use ark_bn254::{Bn254, Fr};
    use ark_groth16::Groth16;
    use ark_snark::SNARK;
    use rand::thread_rng;

    /// Test that we can prove and verify that "abcdef" starts with "abc".
    ///
    /// This test:
    /// 1. Creates a circuit with shorter string "abc" and longer string "abcdef"
    /// 2. Generates a proving key and verification key
    /// 3. Creates a proof that the longer string starts with the shorter string
    /// 4. Verifies the proof using only the shorter string as public input
    #[test]
    fn prove_verify_starts_with() {
        let small = "abc";
        let large = "abcdef";
        let larger_array: PrimeString<Fr> = large.into();
        let shorter_array: PrimeString<Fr> = small.into();

        let circuit = CompareCircuit {
            larger: Some(larger_array.into()),
            shorter: Some(shorter_array.clone().into()),
        };

        let rng = &mut thread_rng();

        let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(circuit.clone(), rng).unwrap();
        let proof = Groth16::<Bn254>::prove(&pk, circuit, rng).expect("proof");
        let verified = Groth16::<Bn254>::verify(&vk, &Vec::<Fr>::from(shorter_array), &proof)
            .expect("verified");

        assert!(verified, "this can't be verified");
    }
}
