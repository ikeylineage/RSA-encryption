# RSA Encryption

A command line RSA encryption tool written in C using OpenSSL.

## Dependencies
- OpenSSL

## Compilation
gcc src/main.c src/keys.c src/encryption_decryption.c src/tests.c -Iinclude -o rsa -lssl -lcrypto

## Usage
./rsa

## How it works
Generates a 2048-bit RSA keypair, encrypts your input and decrypts it back
using modular exponentiation. Includes a test case demonstrating that an 
incorrect private key cannot decrypt the message.

## Notes
- Linux/Mac only, requires OpenSSL to be installed
- Built as a learning project to understand RSA and C
