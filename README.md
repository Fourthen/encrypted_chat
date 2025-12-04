# Secure Chat System (ChaCha20-Poly1305)

This project is a secure, multi-client chat application written in Python.
It allows multiple users to send and receive encrypted messages over a network.

The main goal of this project is to demonstrate how secure communication can be implemented using modern cryptography and networking concepts.

# Features
Multiple clients can connect to one server

End-to-end encrypted messaging

Unique encryption key for each client

Username support

Messages are broadcast to all connected clients

Secure key exchange using Diffie–Hellman

# Technologies Used

Programming Language: Python

Networking: TCP sockets

Multithreading: threading module

Cryptography: PyCryptodome

Encryption: ChaCha20-Poly1305

Key Exchange: Diffie–Hellman

Key Derivation: HKDF (SHA-256)

# How it works

1. The user runs the server on one machine.

2. Other users run the client and connect by using the server’s IP address and a port.

3. When connecting:

- The server and client perform a Diffie–Hellman key exchange

- This creates a shared secret without sending it over the network

4. The shared secret is converted into a 256-bit key using HKDF

5. All messages are encrypted using ChaCha20-Poly1305

6. Messages are sent to the server and then securely broadcast to other users

Everything sent over the network is encrypted. No plaintext messages are visible to eavesdroppers.


**To establish a connection, the client socket must use the correct server IP address and port number. These settings may need to be adjusted depending on the network configuration.**


