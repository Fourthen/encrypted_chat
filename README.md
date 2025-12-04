# Secure Chat System (ChaCha20-Poly1305)

This project is a secure chat system that uses ChaCha20 for encryption and Poly1305 for message authentication. It ensures that all messages are:

Confidential – only intended recipients can read messages.

Authenticated – messages cannot be tampered with undetected.

Integrity-protected – messages are verified before decryption.

The system is built with modern cryptography practices and demonstrates an end-to-end encryption (E2EE) approach.

## Usage 

Usage Example
Encryption
const { encryptMessage } = require("./crypto-utils");

const key = crypto.randomBytes(32);      // 256-bit key
const message = "Hello world!";

const encrypted = encryptMessage(message, key);
console.log(encrypted);

## Decryption
const { decryptMessage } = require("./crypto-utils");

const decrypted = decryptMessage(encrypted, key);
console.log(decrypted); // "Hello world!"
