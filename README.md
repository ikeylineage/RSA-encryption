 C RSA Encryption Utility

A lightweight, CLI-based asymmetric file encryption tool implemented in C using OpenSSL's libcrypto. Demonstrates low-level modular arithmetic, binary file I/O, custom key serialization, and multi-session key persistence.

---

## Technical Highlights

* **2048-Bit RSA Key Generation:** Dynamically generates asymmetric public (n, e) and private (n, d) keypairs using OpenSSL BIGNUM abstractions.
* **Key Serialization & Persistence:** Serializes key components to hexadecimal representations for local disk storage (public.key and private.key) and handles dynamic loading across execution sessions.
* **Raw Binary File I/O:** Reads input files as binary streams, processes data blocks via modular exponentiation, and writes raw ciphertext to dedicated output streams.
* **Resource & Memory Safety:** Utilizes defensive C patterns—including pointer validation (NULL checks), buffer overflow mitigation (fscanf length limits), and stream cleanup—to prevent file leaks and segmentation faults.

---

## Architecture & Mathematical Mechanics

This utility implements core RSA operations via OpenSSL's big-integer engine:

[ Input Stream (in) ] ---> [ Read Bytes ] ---> [ BIGNUM Conversion ] ->
[ BN_mod_exp ] ---> [ Write Bytes ] ---> [ Output Stream (out) ]

* **Encryption:** Converts plaintext blocks into big integers and computes C = M^e mod n.
* **Decryption:** Computes M = C^d mod n using the loaded private exponent (d) and shared modulus (n).

---


## Requirements & Prerequisites

* **Operating System:** Linux or macOS
* **Compiler:** gcc or clang
* **Dependencies:** OpenSSL Development Libraries (libssl-dev on Debian/Ubuntu, openssl via Homebrew on macOS)

---

## Building and Running

### 1. Compile the Source
Navigate to the src/ directory and compile with OpenSSL linkage flags:

cd src
gcc -I../include main.c keys.c encryption_decryption.c -lssl -lcrypto -o rsa_tool

### 2. Execute
Run the compiled binary:

./rsa_tool
