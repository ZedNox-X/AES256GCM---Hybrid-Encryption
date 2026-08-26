from pathlib import Path
from hybridcrypt.core import generate_rsa_keypair, load_private_key, load_public_key, encrypt, decrypt

private_pem, public_pem = generate_rsa_keypair()
public_key = load_public_key(public_pem)
private_key = load_private_key(private_pem)

payload = b"Sensitive enterprise data"
blob = encrypt(payload, public_key, b"application=demo")
plaintext, aad = decrypt(blob, private_key)

assert plaintext == payload
assert aad == b"application=demo"
print("Hybrid encryption round-trip successful.")
