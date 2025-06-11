# Exact: A Rust Library for Fixed-Size ElGamal Encryption

This project provides a Rust implementation of the ElGamal encryption scheme. It focuses on type safety and explicit sizing of cryptographic elements, allowing for serialization and deserialization of keys and ciphertexts.

## Overview

This library provides an implementation of the ElGamal encryption scheme using elliptic curve cryptography (specifically the Ristretto group over Curve25519 via `curve25519-dalek`). A key feature is its emphasis on **fixed-size serialization**: all cryptographic types have a constant, compile-time known byte length. This approach enhances safety, predictability, and performance by ensuring that keys, ciphertexts, and other structures are handled with precise byte representations, reducing parsing ambiguities and potential vulnerabilities associated with variable-length inputs. The core scheme is based on the Diffie–Hellman key exchange.

## Key Modules

The library is organized into the following main modules:

*   **`src/arithmetic.rs`**: Defines fundamental cryptographic arithmetic types.
    *   Includes `Element` (a Ristretto point) and `Exponent` (a scalar value).
    *   Also provides product types `ElementN` (a fixed-size array of `Element`s) and `ExponentN` (a fixed-size array of `Exponent`s).
    *   These types implement the `FSerializable` and `Size` traits for fixed-size byte representation, defined in this module.

*   **`src/serialization.rs`**: Provides the traits and generic structures for fixed-size serialization.
    *   Defines the `Size` trait, indicating a type's compile-time known byte length.
    *   Defines the `FSerializable` trait with `read_bytes` and `write_bytes` methods for conversion to/from byte arrays.
    *   Includes generic structures `Product<LEN, T>` (for fixed-size arrays) and `Pair<T1, T2>` (for pairs of elements), which implement `Size` and `FSerializable`.

*   **`src/elgamal.rs`**: Contains the core ElGamal encryption scheme logic.
    *   Defines `KeyPair` (public and private keys) and `ElGamal` (ciphertext structure for a single element).
    *   Defines `ElGamalN` (ciphertext structure for an array of elements).
    *   Provides the `Encryptable` and `Decryptable` traits, which define a uniform `encrypt` and `decrypt` API.
    *   Implements these traits for `Element`/`ElGamal` and `ElementN`/`ElGamalN` pairs, utilizing `KeyPair`.
    *   All cryptographic structures like `KeyPair`, `ElGamal`, and `ElGamalN` also implement `FSerializable` and `Size`.

*   **`src/lib.rs`**: The main library crate file. It declares and exports the `arithmetic`, `serialization`, and `elgamal` modules. It also enables specific Rust features like `generic_const_exprs` for advanced type-level computation of sizes.

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

**Note on Compiler Version:** This project uses Rust Edition 2024 and features like `generic_const_exprs` which require a nightly Rust compiler. Please ensure you have a nightly toolchain active (e.g., via `rustup override set nightly` in your project directory or by prefixing commands with `cargo +nightly`) to successfully build and test this crate.

## Design Philosophy and Key Features

This library is designed with the following principles and features in mind:

*   **Type Safety:** Leveraging Rust's strong type system to ensure correctness and prevent errors at compile time where possible.
*   **Fixed-Size Serialization:** All core cryptographic types implement the `FSerializable` and `Size` traits, ensuring they have a constant, compile-time known byte length. This approach enhances safety by reducing parsing ambiguities, improves performance, and provides predictability when handling cryptographic data.
*   **Compile-Time Size Calculations:** Utilizes `generic_const_exprs` to work with type sizes at compile time, reinforcing the fixed-size nature of data structures.
*   **Clear Module Separation:** The codebase is organized into distinct modules with clear responsibilities:
    *   `arithmetic`: Fundamental cryptographic types (`Element`, `Exponent`, and their product versions).
    *   `serialization`: Traits (`FSerializable`, `Size`) and generic structures (`Product`, `Pair`) for byte representation.
    *   `elgamal`: The ElGamal encryption scheme logic, key management, and ciphertext structures.
*   **Trait-Based API for Cryptography:** Encryption and decryption operations are exposed via the `Encryptable` and `Decryptable` traits, providing a uniform and extensible interface for cryptographic operations.

## WebAssembly Benchmark

This project includes a WebAssembly (WASM) benchmark for the `prove` function in the Zero-Knowledge Proof module. You can run this benchmark in your web browser.

### Prerequisites

- **Rust and Cargo**: Ensure you have a Rust toolchain installed. If not, visit [rust-lang.org](https://www.rust-lang.org/tools/install).
- **`wasm-pack`**: This tool is used to build Rust-generated WebAssembly. If you don't have it, the `benchmark.ps1` script will attempt to install it, or you can install it manually:
  ```bash
  curl https://rustwasm.github.io/wasm-pack/installer/init.sh -sSf | sh
  ```

### Running the Benchmark

The benchmark can be run using the PowerShell script provided:

1.  **Open PowerShell**: Navigate to the root directory of this project in a PowerShell terminal.
2.  **Execute the script**:
    ```powershell
    .\scripts\benchmark.ps1
    ```
3.  **Script Actions**:
    *   The script will first compile the Rust library to WebAssembly using `wasm-pack build --target web --out-dir www/pkg`.
    *   If the build is successful, it will automatically open the `www/index.html` file in your default web browser.
4.  **In the Browser**:
    *   The opened HTML page contains an input field where you can specify the number of iterations for the `benchmark_prove` function.
    *   Click the "Run Benchmark" button.
    *   The average execution time for the `prove` function over the specified iterations will be displayed on the page.

If the script fails to open the browser automatically, you can manually open the `www/index.html` file in your web browser after a successful build.
