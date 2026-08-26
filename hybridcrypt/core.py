"""AES-256-GCM + RSA-OAEP hybrid encryption."""

from __future__ import annotations

import struct
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAGIC = b"HENC"
VERSION = 1
NONCE_SIZE = 12
AES_KEY_SIZE = 32
MAX_AAD = 16 * 1024 * 1024
MAX_WRAPPED_KEY = 8192
HEADER = struct.Struct(">4sBII")


@dataclass(frozen=True)
class EncryptedPackage:
    wrapped_key: bytes
    nonce: bytes
    aad: bytes
    ciphertext_and_tag: bytes

    def serialize(self) -> bytes:
        if len(self.nonce) != NONCE_SIZE:
            raise ValueError("Invalid GCM nonce length")
        if len(self.aad) > MAX_AAD:
            raise ValueError("AAD is too large")
        if len(self.wrapped_key) > MAX_WRAPPED_KEY:
            raise ValueError("Wrapped key is too large")
        header = HEADER.pack(MAGIC, VERSION, len(self.wrapped_key), len(self.aad))
        return header + self.wrapped_key + self.nonce + self.aad + self.ciphertext_and_tag

    @classmethod
    def deserialize(cls, blob: bytes) -> "EncryptedPackage":
        if len(blob) < HEADER.size + NONCE_SIZE + 16:
            raise ValueError("Encrypted package is truncated")
        magic, version, wrapped_len, aad_len = HEADER.unpack(blob[:HEADER.size])
        if magic != MAGIC:
            raise ValueError("Invalid package magic")
        if version != VERSION:
            raise ValueError(f"Unsupported package version: {version}")
        if wrapped_len > MAX_WRAPPED_KEY or aad_len > MAX_AAD:
            raise ValueError("Package field is too large")

        offset = HEADER.size
        end_wrapped = offset + wrapped_len
        end_nonce = end_wrapped + NONCE_SIZE
        end_aad = end_nonce + aad_len
        if end_aad > len(blob):
            raise ValueError("Encrypted package is truncated")

        wrapped = blob[offset:end_wrapped]
        nonce = blob[end_wrapped:end_nonce]
        aad = blob[end_nonce:end_aad]
        ciphertext = blob[end_aad:]
        if len(ciphertext) < 16:
            raise ValueError("Ciphertext is missing GCM authentication tag")
        return cls(wrapped, nonce, aad, ciphertext)


def generate_rsa_keypair(bits: int = 3072) -> tuple[bytes, bytes]:
    if bits < 2048:
        raise ValueError("RSA key size must be at least 2048 bits")
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    private_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    public_pem = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_pem, public_pem


def load_public_key(pem: bytes):
    key = serialization.load_pem_public_key(pem)
    if not isinstance(key, rsa.RSAPublicKey):
        raise TypeError("Expected an RSA public key")
    return key


def load_private_key(pem: bytes):
    key = serialization.load_pem_private_key(pem, password=None)
    if not isinstance(key, rsa.RSAPrivateKey):
        raise TypeError("Expected an RSA private key")
    return key


def encrypt(plaintext: bytes, public_key, aad: bytes = b"") -> bytes:
    if len(aad) > MAX_AAD:
        raise ValueError("AAD is too large")

    aes_key = AESGCM.generate_key(bit_length=256)
    nonce = AESGCM.generate_key(bit_length=128)[:NONCE_SIZE]
    # Use OS-backed randomness through AESGCM-generated material.
    ciphertext_and_tag = AESGCM(aes_key).encrypt(nonce, plaintext, aad)

    wrapped_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return EncryptedPackage(wrapped_key, nonce, aad, ciphertext_and_tag).serialize()


def decrypt(blob: bytes, private_key) -> tuple[bytes, bytes]:
    package = EncryptedPackage.deserialize(blob)
    aes_key = private_key.decrypt(
        package.wrapped_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    if len(aes_key) != AES_KEY_SIZE:
        raise ValueError("Invalid AES-256 session key")
    plaintext = AESGCM(aes_key).decrypt(
        package.nonce, package.ciphertext_and_tag, package.aad
    )
    return plaintext, package.aad
