# Neutrosophic 1-Round ZKP Implementation in Rust

## 📜 Description

This project provides a Rust implementation of the "Neutrosophic One-Round Zero-Knowledge Proof" protocol as described in the paper by Barbosa and Smarandache. You can download the paper [(https://sciencesforce.com/index.php/plc/article/view/363)].

It also includes an analysis and a corrected, cryptographically sound version of the protocol for educational and comparative purposes.

The primary goal of this repository is to demonstrate the algebraic mechanics of the proposed neutrosophic operations and to critically analyze its cryptographic security.

---

## ⚠️ Security Disclaimer

**The original Neutrosophic 1-Round ZKP protocol implemented here is NOT SECURE and should NOT be used in any production environment.**

Our analysis revealed that the protocol's security is based on a flawed mathematical construction (specifically, a Discrete Logarithm Problem over a composite modulus), making it vulnerable to attacks. This implementation is for **academic and research purposes only**.

---

## ✨ Features

- A `NeutrosophicNumber` struct with implementations for the required mathematical operations (`+`, `*`, `pow_mod`).
- A faithful implementation of the original, **insecure** Neutrosophic 1-Round ZKP.
- A command-line interface to run simulations for both the flawed and the corrected protocols.

---

## 🚀 Getting Started

### Prerequisites

- Rust toolchain (install via [rustup](https://rustup.rs/))
- Git

### Running the Simulation

1. Clone the repository:

   ```bash
   git clone [https://github.com/Ranulfo17/n1rzkp.git](https://github.com/Ranulfo17/n1rzkp.git)
   cd n1rzkp
