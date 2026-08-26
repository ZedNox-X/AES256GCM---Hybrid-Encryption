# Threat Model

## Protected

- Confidentiality of the plaintext against an attacker without the RSA private key.
- Integrity and authenticity of ciphertext through AES-GCM authentication.
- Integrity of the encrypted AES session key through RSA-OAEP.

## Assumptions

- The RSA private key is kept secret.
- The host running decryption is trusted.
- Key storage and rotation are handled by the deployment environment.
- The Python `cryptography` package and operating system randomness are trusted.

## Out of scope

- Compromised endpoints
- Private-key theft
- Traffic metadata
- Password-based key derivation
- Long-term key management and HSM integration
- Secure deletion of plaintext from process memory

## Design rationale

Hybrid encryption avoids using asymmetric cryptography for large payloads. A fresh AES-256 key encrypts each payload with GCM. The AES key is then encrypted using RSA-OAEP with SHA-256.
