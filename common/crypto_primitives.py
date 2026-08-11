#!/usr/bin/env python3
"""Cryptographic primitives used by the artifact scripts."""

from __future__ import annotations

import hashlib
import hmac
import secrets

import oqs


class MLKEMWrapper:
    def __init__(self, variant: str = "ML-KEM-512"):
        self.variant = variant

    def keygen(self):
        kem = oqs.KeyEncapsulation(self.variant)
        pk = kem.generate_keypair()
        sk = kem.export_secret_key()
        return pk, sk

    def encapsulate(self, public_key: bytes):
        kem = oqs.KeyEncapsulation(self.variant)
        ct, ss = kem.encap_secret(public_key)
        return ss, ct

    def decapsulate(self, secret_key: bytes, ciphertext: bytes):
        kem = oqs.KeyEncapsulation(self.variant, secret_key)
        return kem.decap_secret(ciphertext)

    @property
    def public_key_size(self):
        return oqs.KeyEncapsulation(self.variant).details["length_public_key"]

    @property
    def secret_key_size(self):
        return oqs.KeyEncapsulation(self.variant).details["length_secret_key"]

    @property
    def ciphertext_size(self):
        return oqs.KeyEncapsulation(self.variant).details["length_ciphertext"]


class MLDSAWrapper:
    def __init__(self, variant: str = "ML-DSA-44"):
        self.variant = variant
        self.sig = oqs.Signature(variant)

    def keygen(self):
        pk = self.sig.generate_keypair()
        sk = self.sig.export_secret_key()
        return pk, sk

    def sign(self, secret_key: bytes, message: bytes):
        with oqs.Signature(self.variant, secret_key) as signer:
            return signer.sign(message)

    def verify(self, public_key: bytes, message: bytes, signature: bytes):
        try:
            return self.sig.verify(message, signature, public_key)
        except Exception:
            return False

    @property
    def public_key_size(self):
        return oqs.Signature(self.variant).details["length_public_key"]

    @property
    def secret_key_size(self):
        return oqs.Signature(self.variant).details["length_secret_key"]

    @property
    def signature_size(self):
        return oqs.Signature(self.variant).details["length_signature"]


class HKDFWrapper:
    @staticmethod
    def extract(salt: bytes, ikm: bytes):
        if not salt:
            salt = b"\x00" * 32
        return hmac.new(salt, ikm, hashlib.sha256).digest()

    @staticmethod
    def expand(prk: bytes, info: bytes, length: int = 32):
        t = b""
        okm = b""
        counter = 1
        while len(okm) < length:
            t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
            okm += t
            counter += 1
        return okm[:length]

    @staticmethod
    def derive_key(master_key: bytes, context_info: bytes, length: int = 32):
        return HKDFWrapper.expand(HKDFWrapper.extract(b"", master_key), context_info, length)


class HMACWrapper:
    @staticmethod
    def compute(key: bytes, message: bytes):
        return hmac.new(key, message, hashlib.sha256).digest()

    @staticmethod
    def verify(key: bytes, message: bytes, tag: bytes):
        return hmac.compare_digest(HMACWrapper.compute(key, message), tag)


def generate_nonce(size: int = 32):
    return secrets.token_bytes(size)


def hash_transcript(*messages):
    h = hashlib.sha256()
    for msg in messages:
        if isinstance(msg, str):
            msg = msg.encode("utf-8")
        h.update(msg)
    return h.digest()
