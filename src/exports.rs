use crate::circuits::sum::SumCircuit;
use std::os::raw::{c_int, c_uchar};
use std::{mem, slice};

fn convert_to_vec(ptr: *const c_uchar, length: usize) -> Vec<u8> {
    if !ptr.is_null() {
        unsafe {
            return slice::from_raw_parts(ptr, length).to_vec();
        }
    }

    Vec::new()
}

#[no_mangle]
/// Generates a cryptographic proof for a sum operation.
///
/// # Safety
///
/// - `pk` must be a valid pointer to an array of bytes that represents the public key,
///   with `pk_length` specifying the number of bytes in the array.
/// - `out_len` must be a valid pointer to a memory location where the length of the
///   output will be stored. It should not be null unless you intend not to store the length.
/// - The caller must ensure that memory management of the returned pointer is properly handled
///   to avoid leaks or invalid access, using `free_bytes` when the memory is no longer needed.
/// - The function is unsafe due to dereferencing raw pointers and should be called
///   within an `unsafe` block in Rust.
pub unsafe extern "C" fn generate_proof_for_sum(
    pk: *const c_uchar,
    pk_length: usize,
    a: u32,
    b: u32,
    c: u32,
    out_len: *mut c_int,
) -> *mut c_uchar {
    let pk = convert_to_vec(pk, pk_length);
    if let Ok(pk) = crate::circuits::groth16::from_bytes(pk) {
        if let Ok(proof) = crate::circuits::groth16::generate_proof(
            pk,
            SumCircuit::new(Some(a.into()), Some(b.into()), Some(c.into())),
        ) {
            if let Ok(mut proof_bytes) =
                crate::circuits::groth16::TrySerializer::try_to_bytes(proof.as_ref())
            {
                if !out_len.is_null() {
                    *out_len = proof_bytes.len() as c_int;
                }

                let ptr = proof_bytes.as_mut_ptr();

                mem::forget(proof_bytes);

                return ptr as *mut c_uchar;
            }
        }
    }

    std::ptr::null_mut()
}

#[no_mangle]
/// Frees a previously allocated array of bytes.
///
/// # Safety
///
/// The pointer `ptr` must be a valid pointer to memory that was previously
/// allocated by a `Vec<c_uchar>` with exactly `len` elements and `capacity`
/// equal to the original vector's capacity. This function should only be called
/// once for any given allocation to avoid double-free errors. `ptr` must not
/// be null unless `len` and `capacity` are both zero.
pub unsafe extern "C" fn free_bytes(ptr: *mut c_uchar, len: c_int, capacity: c_int) {
    if !ptr.is_null() {
        unsafe {
            // Recreate the Vec and let it drop
            let _ = Vec::from_raw_parts(ptr, len as usize, capacity as usize);
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::circuits::groth16::TrySerializer;

    use super::*;

    fn convert_to_c(v: Vec<u8>) -> (*mut c_uchar, usize) {
        let length = v.len() as usize;
        let mut buffer: Vec<c_uchar> = v.into_iter().map(|x| x as c_uchar).collect();
        let ptr = buffer.as_mut_ptr();

        std::mem::forget(buffer);

        (ptr, length)
    }

    #[test]
    fn test_ffi_sum() {
        let (pk, _) =
            crate::circuits::groth16::setup(SumCircuit::default()).expect("setup of keys");
        let mut out_len: c_int = 0;
        let out_len = &mut out_len;
        let pk = pk.try_to_bytes().expect("serialisation");
        let (pk, pk_length) = convert_to_c(pk);
        unsafe {
            let proof = generate_proof_for_sum(pk, pk_length, 10, 20, 30, out_len);
            assert!(proof != std::ptr::null_mut(), "we should have a proof");
            let p = convert_to_vec(proof, *out_len as usize);
            let p: String = p.iter().map(|b| format!("{:02x}", b)).collect();
            println!("proof: {}", p);
            Vec::from_raw_parts(proof, pk_length, pk_length);
            Vec::from_raw_parts(pk, pk_length, pk_length);
        }
    }
}
