# Architecture

1. Generate a random 256-bit AES session key.
2. Generate a fresh 96-bit GCM nonce.
3. Encrypt plaintext using AES-256-GCM and optional AAD.
4. Encrypt the AES session key with RSA-3072-OAEP-SHA-256.
5. Store the wrapped key, nonce, AAD, and ciphertext/tag in a versioned package.
6. On decryption, recover the AES key using the RSA private key.
7. AES-GCM verifies the authentication tag before returning plaintext.
