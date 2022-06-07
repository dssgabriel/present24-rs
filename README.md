# Cryptography: Man In The Middle attack on a block cipher
This repository is a Rust implementation of the [Attack on 2PRESENT24 C project](https://github.com/dssgabriel/PRESENT24-attack).
The structure of the code is largely the same (and is probably not "_idiomatic_" Rust), however I managed to achieve single core performance that was marginally better than the C implementation (~10% speedup).

## PRESENT24 block cipher specifications
The block cipher implemented in this project is a scaled-down version of
`PRESENT`, a lightweight cipher designed in 2007 by Bogdanov et al. and
standardized in the ISO/IEC 29192-2:2019. The version implemented here
(`PRESENT24`) will take an input message of 24 bits and will produce
a 24 bits ciphertext.

`PRESENT` is part of the Substitution-Permutation Network (SPN) ciphers family.
It is the second main structure type for designing block ciphers, the other
being Feistel Networks.

The concept behind SPN ciphers is simple, each round is composed of three layers:
- A XOR of the subkey to the register.
- A substitution to ensure confusion.
- A permutation to ensure diffusion.

This implementation of `PRESENT24` will perform eleven rounds.


## Usage
### Pre-requisites
- Rust 2018 edition
- Cargo

### Build
```
cargo build --release
```

### Execution
Run by specifying the number of threads that you want to use (4 by default).
```
cargo run --release -- [NB_THREADS]
```
