import pytest
from cryptography.exceptions import InvalidTag

from hybridcrypt.core import decrypt, encrypt, generate_rsa_keypair, load_private_key, load_public_key


@pytest.fixture()
def keys():
    private_pem, public_pem = generate_rsa_keypair(2048)
    return load_private_key(private_pem), load_public_key(public_pem)


def test_round_trip(keys):
    private, public = keys
    message = b"enterprise confidential payload"
    blob = encrypt(message, public, b"tenant=demo")
    plaintext, aad = decrypt(blob, private)
    assert plaintext == message
    assert aad == b"tenant=demo"


def test_tampering_is_detected(keys):
    private, public = keys
    blob = bytearray(encrypt(b"secret", public, b"aad"))
    blob[-1] ^= 1
    with pytest.raises(InvalidTag):
        decrypt(bytes(blob), private)


def test_wrong_key_fails():
    p1, pub1 = generate_rsa_keypair(2048)
    p2, _ = generate_rsa_keypair(2048)
    private1 = load_private_key(p1)
    public1 = load_public_key(pub1)
    private2 = load_private_key(p2)
    blob = encrypt(b"secret", public1)
    with pytest.raises(Exception):
        decrypt(blob, private2)


def test_unique_ciphertexts(keys):
    private, public = keys
    a = encrypt(b"same", public)
    b = encrypt(b"same", public)
    assert a != b
    assert decrypt(a, private)[0] == b"same"
    assert decrypt(b, private)[0] == b"same"
