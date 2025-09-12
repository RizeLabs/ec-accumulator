use ark_bn254::{Bn254, Fr, G1Projective, G2Projective, G1Affine, G2Affine};
use ark_ec::{pairing::Pairing, PrimeGroup,CurveGroup};
use ark_ff::{Field, PrimeField,BigInteger};
use tiny_keccak::{Hasher, Keccak};
use solana_bn254::prelude::alt_bn128_pairing;
use solana_bn254::*;
use solana_bn254::prelude::alt_bn128_multiplication;

/**
 * Description: This struct implements a simple accumulator using the Bn254 curve.
 */

#[derive(Clone)]
 pub struct Bn254Accumulator {
    pub g1: G1Projective,
    pub g2: G2Projective,
    pub acc: G1Projective,
    pub members: Vec<Fr>,
}

impl Bn254Accumulator {
    pub fn new() -> Self {
        let g1 = G1Projective::generator();
        let g2 = G2Projective::generator();
        Self {
            g1,
            g2,
            acc: g1,
            members: Vec::new(),
        }
    }

    /**
     * Description: Hashes the input to a scalar using Keccak256.
     * Method: hash_to_scalar
     * Parameters: input - the input byte array
     * Response: A scalar value of type Fr
     */
    pub fn hash_to_scalar(input: &[u8]) -> Fr {
        let mut keccak = Keccak::v256();
        let mut hash = [0u8; 32];
        keccak.update(input);
        keccak.finalize(&mut hash);
        Fr::from_be_bytes_mod_order(&hash)
    }

    /**
     * Description: Adds a member to the accumulator.
     * Method: add_member
     * Parameters: member - the member to be added
     * Response: The scalar value of the member
     */
    pub fn add_member(&mut self, member: &[u8]) -> Fr {
        let x = Self::hash_to_scalar(member);
        self.acc *= x;
        self.members.push(x);
        x
    }

    /**
     * Description: Calculates the witness for verifying membership proof of a particular member.
     * Method: membership_witness
     * Parameters: member whose witness needs to be calculated
     * Response: witness for verifying the inclusion of particular member
     */
    pub fn membership_witness(&self, x: Fr) -> Option<G1Projective> {
        // Compute product of all x_i except x
        let mut product = Fr::ONE;
        let mut found = false;
        for xi in &self.members {
            if *xi == x && !found {
                found = true; // skip only the first occurrence
                continue;
            }
            product *= xi;
        }

        if found {
            Some(self.g1 * product)
        } else {
            None
        }
    }
      pub fn ark_g1_to_pod(p: &G1Projective) -> PodG1 {
        let affine: G1Affine = (*p).into_affine();
        let mut out = [0u8; 64];
        out[..32].copy_from_slice(&affine.x.into_bigint().to_bytes_be());
        out[32..64].copy_from_slice(&affine.y.into_bigint().to_bytes_be());
        PodG1(out)
    }

    pub fn ark_g2_to_pod(p: &G2Projective) -> PodG2 {
        let affine: G2Affine = (*p).into_affine();
        let mut out = [0u8; 128];
        // Ethereum order: x_c1, x_c0, y_c1, y_c0
        out[0..32].copy_from_slice(&affine.x.c1.into_bigint().to_bytes_be());
        out[32..64].copy_from_slice(&affine.x.c0.into_bigint().to_bytes_be());
        out[64..96].copy_from_slice(&affine.y.c1.into_bigint().to_bytes_be());
        out[96..128].copy_from_slice(&affine.y.c0.into_bigint().to_bytes_be());
        PodG2(out)
    }
    fn fr_to_solana_scalar(fr: &Fr) -> [u8; 32] {
    let big = fr.into_bigint();              
    let mut bytes = big.to_bytes_be();        
    let mut out = [0u8; 32];

    // left-pad with zeros
    out[32 - bytes.len()..].copy_from_slice(&bytes);
    out
}

    /**
     * Description: Verifies the membership of a member in the accumulator.
     * Method: verify_membership
     * Parameters: x - the member to be verified, witness - the witness for the member
     * Response: true if the member is in the accumulator, false otherwise
     */
    pub fn verify_membership(&self, x: Fr, witness: G1Projective) -> bool {
        let lhs = Bn254::pairing(witness * x, self.g2);
        let rhs = Bn254::pairing(self.acc, self.g2);
        lhs == rhs
    }

     /// G1 → 64-byte BE
    fn g1_to_bytes(point: &G1Projective) -> Result<[u8; 64], Box<dyn std::error::Error>> {
        let affine = point.into_affine();
        let mut out = [0u8; 64];
        let x_be = affine.x.into_bigint().to_bytes_be();
        let y_be = affine.y.into_bigint().to_bytes_be();
        out[0..32].copy_from_slice(&x_be);
        out[32..64].copy_from_slice(&y_be);
        Ok(out)
    }

    /// G2 → 128-byte BE: x.c1||x.c0||y.c1||y.c0
    fn g2_to_bytes(point: &G2Projective) -> Result<[u8; 128], Box<dyn std::error::Error>> {
        let affine = point.into_affine();
        let mut out = [0u8; 128];
        let x_c0 = affine.x.c0.into_bigint().to_bytes_be();
        let x_c1 = affine.x.c1.into_bigint().to_bytes_be();
        let y_c0 = affine.y.c0.into_bigint().to_bytes_be();
        let y_c1 = affine.y.c1.into_bigint().to_bytes_be();
        out[0..32].copy_from_slice(&x_c1);
        out[32..64].copy_from_slice(&x_c0);
        out[64..96].copy_from_slice(&y_c1);
        out[96..128].copy_from_slice(&y_c0);
        Ok(out)
    }
     /// Verifies membership by constructing a single 384-byte input array.
    pub fn verify_membership_solana(
        &self,
        x: Fr,
        witness: G1Projective,
    ) -> Result<bool, Box<dyn std::error::Error>> {
        // 1. Compute `witness * x` and serialize to 64 bytes.
        let wx = witness * x;
        let wx_bytes = Self::g1_to_bytes(&wx)?;
        // 2. Serialize G2 generator to 128 bytes.
        let g2_bytes = Self::g2_to_bytes(&self.g2)?;
        // 3. Negate accumulator and serialize to 64 bytes.
        let acc_neg = -self.acc;
        let acc_bytes = Self::g1_to_bytes(&acc_neg)?;
        // 4. Build a single [u8;384] buffer.
        let mut input = [0u8; 384];
        input[0..64].copy_from_slice(&wx_bytes);
        input[64..192].copy_from_slice(&g2_bytes);
        input[192..256].copy_from_slice(&acc_bytes);
        input[256..384].copy_from_slice(&g2_bytes);

        // 5. Call the syscall over the fixed-size array.
        let res = alt_bn128_pairing(&input).map_err(|_| "alt_bn128_pairing syscall failed")?;

        // Last byte == 1 indicates the pairing product is identity.
        Ok(res[31] == 1)
    }

pub fn verify_membership_solana2(
    &self,
    x: Fr,
    witness: G1Projective,
) -> Result<bool, Box<dyn std::error::Error>> {
    println!("Starting membership verification...");
    
    // 1. Compute `witness * x` using Solana syscall
    let w = Self::ark_g1_to_pod(&witness);
    let x_bytes = Self::fr_to_solana_scalar(&x);
    
    println!("Witness POD bytes length: {}", w.0.len());
    println!("X scalar bytes length: {}", x_bytes.len());
    
    let mut input = [0u8; 96];
    input[0..64].copy_from_slice(&w.0);
    input[64..96].copy_from_slice(&x_bytes);
    
    println!("About to call alt_bn128_multiplication for witness*x...");
    let wx_bytes = match alt_bn128_multiplication(&input) {
        Ok(result) => {
            println!("Successfully computed witness*x, result length: {}", result.len());
            result
        },
        Err(e) => {
            println!("Error in witness*x multiplication: {:?}", e);
            return Err(Box::new(std::io::Error::new(std::io::ErrorKind::InvalidData, "witness*x multiplication failed")));
        }
    };
    
    let mut wx_pod_bytes = [0u8; 64];
    wx_pod_bytes.copy_from_slice(&wx_bytes);
    let wx_pod = PodG1(wx_pod_bytes);

    // 2. Get G2 generator in POD format
    let g2_pod = Self::ark_g2_to_pod(&self.g2);
    println!("G2 POD bytes length: {}", g2_pod.0.len());

    // 3. Compute accumulator * (-1) using Solana syscall
    let acc_pod = Self::ark_g1_to_pod(&self.acc);
    let neg_one_scalar = Self::fr_to_solana_scalar(&Fr::from(-1));
    
    println!("Acc POD bytes length: {}", acc_pod.0.len());
    println!("Neg one scalar bytes length: {}", neg_one_scalar.len());
    
    let mut acc_input = [0u8; 96];
    acc_input[0..64].copy_from_slice(&acc_pod.0);
    acc_input[64..96].copy_from_slice(&neg_one_scalar);
    
    println!("About to call alt_bn128_multiplication for acc*(-1)...");
    let acc_neg_bytes = match alt_bn128_multiplication(&acc_input) {
        Ok(result) => {
            println!("Successfully computed acc*(-1), result length: {}", result.len());
            result
        },
        Err(e) => {
            println!("Error in acc*(-1) multiplication: {:?}", e);
            return Err(Box::new(std::io::Error::new(std::io::ErrorKind::InvalidData, "acc*(-1) multiplication failed")));
        }
    };
    
    let mut acc_neg_pod_bytes = [0u8; 64];
    acc_neg_pod_bytes.copy_from_slice(&acc_neg_bytes);
    let acc_neg_pod = PodG1(acc_neg_pod_bytes);

    // 4. Build pairing input using POD representations
    let mut pairing_input = [0u8; 384];
    pairing_input[0..64].copy_from_slice(&wx_pod.0);
    pairing_input[64..192].copy_from_slice(&g2_pod.0);
    pairing_input[192..256].copy_from_slice(&acc_neg_pod.0);
    pairing_input[256..384].copy_from_slice(&g2_pod.0);

    println!("About to call alt_bn128_pairing...");
    // 5. Call the pairing syscall
    let res = match alt_bn128_pairing(&pairing_input) {
        Ok(result) => {
            println!("Successfully computed pairing, result: {:?}", result);
            result
        },
        Err(e) => {
            println!("Error in pairing: {:?}", e);
            return Err(Box::new(std::io::Error::new(std::io::ErrorKind::InvalidData, "pairing failed")));
        }
    };

    let is_valid = res[31] == 1;
    println!("Pairing result (last byte): {}, is_valid: {}", res[31], is_valid);
    Ok(is_valid)
}}



#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_membership_proof() {
        let mut acc = Bn254Accumulator::new();

        let members: Vec<&[u8]> = vec![b"alice", b"bob", b"charlie"];
        let scalars: Vec<Fr> = members.iter().map(|m| acc.add_member(*m)).collect();

        for (i, x) in scalars.iter().enumerate() {
            let witness = acc.membership_witness(*x).unwrap();
            let valid = acc.verify_membership(*x, witness);
            assert!(valid, "Proof failed for member index {}", i);
        }
    }

    #[test]
    fn test_non_member_should_fail() {
        let mut acc = Bn254Accumulator::new();

        let _ = acc.add_member(b"alice");
        let _ = acc.add_member(b"bob");

        let fake = Bn254Accumulator::hash_to_scalar(b"mallory");
        let fake_witness = acc.membership_witness(fake);

        assert!(
            fake_witness.is_none(),
            "Non-member should not have a witness"
        );
    }

        #[test]
    fn test_membership_verification_and_failure() {
        let mut acc = Bn254Accumulator::new();
        let x1 = acc.add_member(b"alice");
        let x2 = acc.add_member(b"bob");

        let w2 = acc.membership_witness(x2).unwrap();
        assert!(acc.verify_membership_solana2(x2, w2).unwrap());

        // Wrong witness for x2
        let w1 = acc.membership_witness(x1).unwrap();
        assert!(!acc.verify_membership_solana2(x2, w1).unwrap());
    }


}
