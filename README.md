# AES-256-GCM Hybrid Encryption.

A GitHub-ready reference implementation of hybrid encryption
- AES-256-GCM for authenticated bulk encryption
- RSA-3072-OAEP-SHA-256 for wrapping the AES session key
- Random 96-bit GCM nonces
- AAD support
- Key generation and CLI workflows
- Tamper detection
- Unit tests

<img width="1536" height="1024" alt="AES" src="https://github.com/user-attachments/assets/ffda4809-6b9b-4ae5-96a0-643c3b2d1eaf" />
## Architecture

Plaintext -> AES-256-GCM -> Ciphertext
                    |
              AES session key
                    |
             RSA-3072-OAEP
                    |
             Encrypted key

The recipient uses the RSA private key to recover the AES session key, then verifies and decrypts the ciphertext.

## Requirements

- Python 3.10+
- `cryptography`

Install:

```bash
python -m pip install -r requirements.txt
```

## Quick start

Generate an RSA key pair:

```bash
python -m hybridcrypt.cli keygen --out keys
```

Encrypt:

```bash
python -m hybridcrypt.cli encrypt   --public-key keys/public.pem   --input examples/message.txt   --output examples/message.enc   --aad "enterprise-demo"
```

Decrypt:

```bash
python -m hybridcrypt.cli decrypt   --private-key keys/private.pem   --input examples/message.enc   --output examples/message.dec.txt   --aad "enterprise-demo"
```

The encrypted package is a versioned binary container containing the RSA-wrapped AES key, GCM nonce, authentication tag, AAD, and ciphertext.

## Security notes.

This project is an educational/reference implementation, not a replacement for a reviewed production cryptosystem. Private keys must be protected with appropriate OS permissions, secret storage, rotation, and operational controls

AES-GCM provides confidentiality and integrity only when nonces are never reused with the same key. This implementation generates a fresh random AES-256 key for every encryption operation, making nonce reuse across encryption operations impossible.

RSA-OAEP is used only for encrypting the randomly generated AES key. RSA is not used to encrypt the bulk payload.

Updated on 1st September 2026 by Melbin George
