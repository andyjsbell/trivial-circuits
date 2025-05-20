use ark_bn254::Bn254;
use ark_ec::pairing::Pairing;
use ark_groth16::{Groth16, Proof, ProvingKey, VerifyingKey};
use ark_relations::r1cs::ConstraintSynthesizer;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_snark::SNARK;
use rand::thread_rng;

#[derive(Clone, Debug, PartialEq)]
pub struct Bn254Proof(pub Proof<Bn254>);

impl AsRef<Proof<Bn254>> for Bn254Proof {
    fn as_ref(&self) -> &Proof<Bn254> {
        &self.0
    }
}

impl From<Proof<Bn254>> for Bn254Proof {
    fn from(proof: Proof<Bn254>) -> Self {
        Bn254Proof(proof)
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

pub fn from_bytes<T>(bytes: Vec<u8>) -> Result<T, String>
where
    T: CanonicalDeserialize,
{
    T::deserialize_uncompressed(bytes.as_slice()).map_err(|e| e.to_string())
}

pub fn setup<C>(c: C) -> Result<(ProvingKey<Bn254>, VerifyingKey<Bn254>), String>
where
    C: ConstraintSynthesizer<<Bn254 as Pairing>::ScalarField>,
{
    Groth16::<Bn254>::circuit_specific_setup(c, &mut thread_rng()).map_err(|e| e.to_string())
}

pub fn generate_proof<C>(pk: ProvingKey<Bn254>, c: C) -> Result<Bn254Proof, String>
where
    C: ConstraintSynthesizer<<Bn254 as Pairing>::ScalarField>,
{
    Ok(Groth16::<Bn254>::prove(&pk, c, &mut thread_rng())
        .map_err(|e| e.to_string())?
        .into())
}

pub fn verify_proof(
    vk: VerifyingKey<Bn254>,
    public_input: &[<Bn254 as Pairing>::ScalarField],
    proof: Bn254Proof,
) -> Result<bool, String> {
    Groth16::<Bn254>::verify(&vk, public_input, proof.as_ref()).map_err(|e| e.to_string())
}
