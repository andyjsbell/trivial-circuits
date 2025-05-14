# Trivial Circuits

A simple Rust project demonstrating basic zero-knowledge proof circuits using the [arkworks](https://arkworks.rs/) libraries.

## Overview

This project implements two simple zero-knowledge proof circuits:

1. **Sum Circuit** - Proves knowledge of two private numbers that sum to a public value
2. **Compare Circuit** - Proves that a longer string starts with a specified shorter string

These circuits demonstrate how to use the arkworks libraries to create zero-knowledge proofs with the Groth16 proving system on the BN254 elliptic curve.

## Prerequisites

- Rust and Cargo (1.60+ recommended)

## Installation

Clone the repository and build:

```bash
git clone https://github.com/yourusername/trivial-circuits.git
cd trivial-circuits
cargo build
```

## Usage

### Running Tests

To run the tests for both circuits:

```bash
cargo test
```

### Sum Circuit

The sum circuit proves that you know two values `a` and `b` that add up to a public value `c`.

```rust
// Example: Prove you know values a=10 and b=32 such that a+b=42
let circuit = SumCircuit {
    a: Some(10.into()),
    b: Some(32.into()),
    c: Some(42.into()),
};
```

### Compare Circuit

The compare circuit proves that a longer string starts with a shorter string, without revealing the entire longer string.

```rust
// Example: Prove that the string "abcdef" starts with "abc"
let small = "abc";
let large = "abcdef";
let circuit = CompareCircuit {
    larger: Some(larger_array.into()),
    shorter: Some(shorter_array.into()),
};
```

## Project Structure

```
trivial-circuits/
├── src/
│   ├── circuits/
│   │   ├── mod.rs
│   │   ├── sum.rs      # Sum circuit implementation
│   │   └── compare.rs  # String comparison circuit implementation
│   └── lib.rs
├── Cargo.toml
└── README.md
```

## Technical Details

### Zero-Knowledge Proofs

This project uses zk-SNARKs (Zero-Knowledge Succinct Non-Interactive Arguments of Knowledge) to create proofs that certain statements are true without revealing the underlying private data.

### Libraries Used

- **ark-ff**: Finite field implementations
- **ark-relations**: Constraint system definitions
- **ark-r1cs-std**: Standard gadget implementations for R1CS
- **ark-groth16**: Implementation of the Groth16 proving system
- **ark-bn254**: Implementation of the BN254 (Barreto-Naehrig) elliptic curve
- **ark-snark**: Common SNARK traits
- **rand**: Random number generation

## License

[MIT License](LICENSE)

## Contributions

Contributions are welcome! Please feel free to submit a Pull Request.