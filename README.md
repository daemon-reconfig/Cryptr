# Crypter - Encrypted Payload Generator

Crypter is a CLI-based tool designed to **encrypt payloads** and **generate executable stubs** for execution.  
It supports **AES-256** and **ChaCha20** encryption with customizable output formats.

## Features
-  **Supports EXE and DLL generation**
-  **AES-256 / ChaCha20 encryption support**
-  **Command-line arguments for flexibility**
-  **Interactive CLI with verbose output**
-  **Colorized output for clarity**
-  **Robust stub compilation and error handling**

---

## Installation

Ensure you have **Rust** installed:
```sh
rustc --version
```
If Rust is missing, install it via:
```sh
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```
Clone this repository 
```sh
git clone https://github.com/yourrepo/crypter.git
cd crypter
cargo build --release
```
---

## Usage

Basic Syntax:
```sh
./crypter -i <input file> -o <output file> -e <exe|dll> -m <aes|cha> [-v]
```
---

## How It Works
1) Reads the input payload.
2) Encrypts it using the selected encryption algorithm.
3) Generates a stub executable that decrypts and runs the payload at execution.
4) Uses Rust's cargo build to compile the final EXE or DLL.

---

## Stub Execution
- The stub contains embedded encrypted payload.
- Upon execution, it decrypts and executes the payload in memory.
- Uses AES-256-GCM or ChaCha20Poly1305 for secure encryption.

---

## Phases The Project Will Go Through

### Phase 1: Core Crypter Functionality (Encryption & Execution) – [IN PROGRESS]
✅ Implement CLI for EXE/DLL encryption selection.
✅ Support AES-256 and ChaCha20 for encryption.
✅ Develop a decryption stub that executes payloads.
🔄 Integrate process hollowing (partially done, needs refinement).
🔄 Implement syscall obfuscation (work in progress).

### Phase 2: Evasion & Obfuscation
🔲 Encrypt stub sections to hinder static analysis.
🔲 Implement polymorphic techniques (e.g., junk code insertion).
🔲 Modify PE structure to avoid common signatures.
🔲 Implement in-memory execution for stealth.

### Phase 3: Persistence & Payload Execution Variants
🔲 Implement optional registry-based persistence.
🔲 Add scheduled task execution.
🔲 Support multiple payload execution methods (DLL injection, APC queue, etc.).

### Phase 4: Final Testing & Optimization
🔲 Test against different Windows versions.
🔲 Improve stub efficiency (reduce size, optimize performance).
🔲 Validate against common AV/EDR solutions.
🔲 Implement automated payload generation.


