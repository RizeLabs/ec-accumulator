use ark_bn254::{Fr, G1Projective, G2Projective};
use ark_ec::CurveGroup;
use ark_ec::PrimeGroup;
use ark_ff::BigInteger;
use ark_ff::PrimeField;
use solana_bn254::prelude::alt_bn128_pairing;

pub struct SolanaBn254Accumulator {
    pub g1: G1Projective,
    pub g2: G2Projective,
    pub acc: G1Projective,
    pub members: Vec<Fr>,
}

impl SolanaBn254Accumulator {
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
    use ark_bn254::Fr;
    use ark_bn254::{G1Projective, G2Projective};
    use ark_ff::Field;
    use tiny_keccak::{Hasher, Keccak};

    fn hash_to_scalar(input: &[u8]) -> Fr {
        let mut hasher = Keccak::v256();
        let mut buf = [0u8; 32];
        hasher.update(input);
        hasher.finalize(&mut buf);
        Fr::from_be_bytes_mod_order(&buf)
    }
    fn new_acc() -> SolanaBn254Accumulator {
        SolanaBn254Accumulator {
            g1: G1Projective::generator(),
            g2: G2Projective::generator(),
            acc: G1Projective::generator(),
            members: Vec::new(),
        }
    }

    fn add_member(acc: &mut SolanaBn254Accumulator, name: &[u8]) -> Fr {
        let x = hash_to_scalar(name);
        acc.acc *= x;
        acc.members.push(x);
        x
    }

    fn membership_witness(acc: &SolanaBn254Accumulator, x: Fr) -> Option<G1Projective> {
        let mut prod = Fr::ONE;
        let mut skip = false;
        for &xi in &acc.members {
            if xi == x && !skip {
                skip = true;
                continue;
            }
            prod *= xi;
        }
        if skip {
            Some(acc.g1 * prod)
        } else {
            None
        }
    }

    #[test]
    fn test_membership_verification_and_failure() {
        let mut acc = new_acc();
        let x1 = add_member(&mut acc, b"alice");
        let x2 = add_member(&mut acc, b"bob");

        let w2 = membership_witness(&acc, x2).unwrap();
        assert!(acc.verify_membership_solana(x2, w2).unwrap());

        // Wrong witness for x2
        let w1 = membership_witness(&acc, x1).unwrap();
        assert!(!acc.verify_membership_solana(x2, w1).unwrap());
    }
}
