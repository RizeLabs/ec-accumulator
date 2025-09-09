use ark_bn254::{Bn254, Fr, G1Projective, G2Projective};
use ark_ec::{pairing::Pairing, PrimeGroup,CurveGroup};
use ark_ff::{Field, PrimeField,BigInteger};
use tiny_keccak::{Hasher, Keccak};
use solana_bn254::prelude::alt_bn128_pairing;

/**
 * Description: This struct implements a simple accumulator using the Bn254 curve.
 */
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
        // Offsets: 0, 64, 192, 256
        input[0..64].copy_from_slice(&wx_bytes);
        input[64..192].copy_from_slice(&g2_bytes);
        input[192..256].copy_from_slice(&acc_bytes);
        input[256..384].copy_from_slice(&g2_bytes);

        // 5. Call the syscall over the fixed-size array.
        let res = alt_bn128_pairing(&input).map_err(|_| "alt_bn128_pairing syscall failed")?;

        // Last byte == 1 indicates the pairing product is identity.
        Ok(res[31] == 1)
    }

}

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
        assert!(acc.verify_membership_solana(x2, w2).unwrap());

        // Wrong witness for x2
        let w1 = acc.membership_witness(x1).unwrap();
        assert!(!acc.verify_membership_solana(x2, w1).unwrap());
    }


}
