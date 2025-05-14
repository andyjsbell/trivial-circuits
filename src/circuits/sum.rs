use ark_ff::PrimeField;
use ark_r1cs_std::{alloc::AllocVar, eq::EqGadget, fields::fp::FpVar};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

#[derive(Clone)]
pub struct SumCircuit<F: PrimeField> {
    pub a: Option<F>,
    pub b: Option<F>,
    pub c: Option<F>,
}

impl<F: PrimeField> ConstraintSynthesizer<F> for SumCircuit<F> {
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
    use ark_bn254::Bn254;
    use ark_groth16::Groth16;
    use ark_snark::SNARK;
    use rand::thread_rng;

    use super::*;

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

    #[test]
    #[should_panic(expected = "assertion failed: cs.is_satisfied().unwrap()")]
    fn prove_verify_bad_sum() {
        let c = 42;
        let a = 10;
        let b = 31;

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
