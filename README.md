# BN254 Accumulator

This Rust crate provides a simple cryptographic accumulator based on the [BN254 pairing-friendly elliptic curve](https://eips.ethereum.org/EIPS/eip-197), using the `arkworks` ecosystem. The accumulator supports membership proofs, which can be verified on-chain using Ethereum's pairing precompile.

## ✨ Features
- Deterministic hashing of arbitrary data to `Fr` scalars using `keccak256`
- Accumulation of elements using exponentiation in G1
- Generation of membership witnesses
- Verification of membership via bilinear pairing
- On-chain verifiability with Ethereum precompiles

## 🔍 Background
The accumulator stores a product of hashed inputs as a G1 group element:
```
A = g1^{x1 * x2 * ... * xn}
```
To prove membership of `xi`, a witness is computed:
```
witness = g1^{product of all xj where j ≠ i}
```
Verification is done via:
```
e(witness^xi, g2) == e(A, g2)
```

## 🚀 Usage
```rust
let mut acc = Bn254Accumulator::new();

let member = b"hello world";
let x = acc.add_member(member);

let witness = acc.membership_witness(x).unwrap();
let is_valid = acc.verify_membership(x, witness);
println!("Proof valid: {}", is_valid);
```

## 🧪 Tests
Two basic tests are included:
- `test_membership_proof`: Ensures all added members generate valid proofs
- `test_non_member_should_fail`: Ensures a non-member fails proof generation

## 🔐 On-chain Integration
Use Ethereum's pairing precompile at address `0x08` to verify proofs. Convert the accumulator value (`G1Projective`) to affine coordinates and pass the `x`, `y` components to Solidity as `uint256[2]`.

Example Solidity representation:
```solidity
struct G1Point {
    uint256 x;
    uint256 y;
}
```

## 📦 Dependencies
- [arkworks](https://github.com/arkworks-rs) ecosystem: `ark-ec`, `ark-ff`, `ark-bn254`
- [tiny-keccak](https://crates.io/crates/tiny-keccak): For `keccak256` hashing

## 📁 File Structure
- `Bn254Accumulator`: Core logic for accumulation, witness generation, and verification
- `main()`: Simple usage example
- `#[cfg(test)]`: Test suite for validation

## ⚠️ Security Note
This accumulator relies on a trusted setup of group generators. For production use, ensure generators are either fixed from a secure source (e.g., Ethereum alt-BN254 spec) or auditable.

---
Made with ❤️ using zk-friendly curves.
