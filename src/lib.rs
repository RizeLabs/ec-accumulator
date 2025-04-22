use ark_bn254::{Bn254, Fr, G1Projective, G2Projective};
use ark_ec::{pairing::Pairing, PrimeGroup};
use ark_ff::{Field, PrimeField};
use tiny_keccak::{Hasher, Keccak};

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
        Fr::from_le_bytes_mod_order(&hash)
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

        assert!(fake_witness.is_none(), "Non-member should not have a witness");
    }
}