# Exact: ElGamal Encryption in Rust

This project provides a Rust implementation of the ElGamal encryption scheme. It focuses on type safety and explicit sizing of cryptographic elements, allowing for serialization and deserialization of keys and ciphertexts.

## Overview

The ElGamal encryption scheme is an asymmetric key encryption algorithm for public-key cryptography which is based on the Diffie–Hellman key exchange. This implementation uses elliptic curve cryptography, specifically the Ristretto group over Curve25519, provided by the `curve25519-dalek` library.

## Key Modules

The library is organized into the following main modules:

*   **`src/elgamal.rs`**: Contains the core ElGamal encryption logic.
    *   Defines `Exponent` (a scalar value on the curve) and `Element` (a Ristretto point on the curve) types.
    *   Implements `KeyPair` generation (public and private keys).
    *   Provides functions for encrypting and decrypting individual `Element`s.
    *   Supports batch operations for encrypting and decrypting arrays of `Element`s (via `ElementN` and `ElGamalN` types).
    *   Includes comprehensive unit tests to verify the correctness of cryptographic operations and serialization.

*   **`src/size.rs`**: Provides traits and generic data structures for handling the serialization and deserialization of cryptographic types.
    *   The `Size` trait defines a `SIZE` constant for types, indicating their fixed byte length.
    *   The `Parseable` trait defines `parse` (from bytes) and `write` (to bytes) methods.
    *   Generic structures `Product<LEN, T>` (for fixed-size arrays) and `Pair<T1, T2>` (for pairs of elements) implement `Size` and `Parseable`, enabling structured data handling.

*   **`src/lib.rs`**: The main library crate file. It declares the `elgamal` and `size` modules and enables specific Rust features like `generic_const_exprs` for advanced type-level computation of sizes.

## Dependencies

This project relies on the following external crates:

*   `curve25519-dalek`: For elliptic curve operations using the Ristretto group.
*   `rand`: For secure random number generation required during key generation and encryption.

## Building and Testing

The project uses Cargo, the Rust build system and package manager.

### Build
To build the library, run:
```bash
cargo build
```

### Test
To run the unit tests included in the library, execute:
```bash
cargo test
```

This will verify the correctness of the ElGamal implementation, including key generation, encryption, decryption, and serialization/deserialization logic.
