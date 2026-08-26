from __future__ import annotations

import argparse
import getpass
import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization

from .core import decrypt, encrypt, generate_rsa_keypair, load_private_key, load_public_key


def _write_private(path: Path, data: bytes) -> None:
    path.write_bytes(data)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def keygen(args):
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    private_pem, public_pem = generate_rsa_keypair(args.bits)
    _write_private(out / "private.pem", private_pem)
    (out / "public.pem").write_bytes(public_pem)
    print(f"Generated RSA-{args.bits} key pair in {out}")


def encrypt_cmd(args):
    public_key = load_public_key(Path(args.public_key).read_bytes())
    aad = args.aad.encode()
    blob = encrypt(Path(args.input).read_bytes(), public_key, aad)
    Path(args.output).write_bytes(blob)
    print(f"Encrypted {args.input} -> {args.output}")


def decrypt_cmd(args):
    private_key = load_private_key(Path(args.private_key).read_bytes())
    plaintext, aad = decrypt(Path(args.input).read_bytes(), private_key)
    if args.aad is not None and aad != args.aad.encode():
        raise SystemExit("AAD mismatch")
    Path(args.output).write_bytes(plaintext)
    print(f"Decrypted {args.input} -> {args.output}")


def build_parser():
    p = argparse.ArgumentParser(description="AES-256-GCM hybrid encryption")
    sub = p.add_subparsers(required=True)

    k = sub.add_parser("keygen", help="Generate RSA key pair")
    k.add_argument("--out", required=True)
    k.add_argument("--bits", type=int, default=3072)
    k.set_defaults(func=keygen)

    e = sub.add_parser("encrypt", help="Encrypt a file")
    e.add_argument("--public-key", required=True)
    e.add_argument("--input", required=True)
    e.add_argument("--output", required=True)
    e.add_argument("--aad", default="")
    e.set_defaults(func=encrypt_cmd)

    d = sub.add_parser("decrypt", help="Decrypt a file")
    d.add_argument("--private-key", required=True)
    d.add_argument("--input", required=True)
    d.add_argument("--output", required=True)
    d.add_argument("--aad")
    d.set_defaults(func=decrypt_cmd)
    return p


def main():
    args = build_parser().parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
