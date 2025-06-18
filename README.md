# dh-rsa-aes-messaging

A Python-based toolkit implementing: (1) a Diffie‑Hellman key‑exchange pair (client/server), (2) RSA key‑generation and digital‐signature client, and (3) authenticated AES‑CBC encryption with HMAC. Perfect for learning cryptographic protocols end‑to‑end.

🚀 Project Overview

This homework assignment covers three core cryptography tasks:

Diffie‑Hellman Key Exchange• Standalone server (--s) and client (--c) on localhost port 9999• Derives shared secret K = gᵃᵇ mod p and prints it to stdout

RSA Digital Signatures• Generates 3072‑bit RSA keypair (--genkey)• Client mode (--c) connects to a socket, hashes and signs input messages, then sends signature payload

AES‑CBC Authenticated Encryption• Symmetric encryption/decryption with AES‑CBC and HMAC‑SHA256
• encrypt_message() and decrypt_message() functions manage IVs, padding, and integrity checks

🗂️ File Structure

    ├── dh.py          # Diffie‑Hellman server/client
    ├── signer.py      # RSA keygen & signing client
    └── encryptedim.py # AES‑CBC + HMAC authenticated encryption

Note: macOS metadata (__MACOSX/, .DS_Store) omitted for clarity.

🏃‍♂️ Usage Examples

1. Diffie‑Hellman Key Exchange

Start server on one terminal:

python dh.py --s

Run client in another terminal (replace 127.0.0.1 if remote):

python dh.py --c 127.0.0.1

The client prints the shared secret K.

2. RSA Digital Signatures

Generate keypair:

python signer.py --genkey

Creates mypubkey.pem & myprivatekey.pem in working directory.

Sign messages (example):

echo "Hello, world" | python signer.py --c 127.0.0.1

Sends message and signature to server at 127.0.0.1:9999.

3. AES‑CBC Authenticated Encryption

Import functions in your own script:

from encryptedim import encrypt_message, decrypt_message

# generate keys
Ek1 = get_random_bytes(16)
HMACk2 = get_random_bytes(16)

# encrypt
ciphertext = encrypt_message(b"Secret data", Ek1, HMACk2)

# decrypt
plaintext = decrypt_message(ciphertext, Ek1, HMACk2)

Refer to the docstrings in encryptedim.py for padding, IV handling, and HMAC verification details.

📝 Notes & Citations

• AES examples inspired by PyCryptodome docs (CBC, padding):https://pycryptodome.readthedocs.io/en/latest/src/examples.html

• HMAC & RSA signature examples inspired by PyCryptodome:https://pycryptodome.readthedocs.io/en/latest/src/signature/pkcs1_v1_5.html
