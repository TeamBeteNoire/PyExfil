import os
import pytest

from pyexfil.includes.encryption_wrappers import (
    AESEncryptOFB, AESDecryptOFB, RC4, GenerateHMAC, VerifyHMAC
)


class TestAESOFB:

    def test_roundtrip_bytes_key(self):
        key = b"mysecretkey"
        plaintext = b"Hello, PyExfil!"
        ciphertext = AESEncryptOFB(key, plaintext)
        assert ciphertext != plaintext
        result = AESDecryptOFB(key, ciphertext)
        assert result == plaintext

    def test_roundtrip_str_key(self):
        key = "mysecretkey"
        plaintext = b"Test data 1234"
        ciphertext = AESEncryptOFB(key, plaintext)
        result = AESDecryptOFB(key, ciphertext)
        assert result == plaintext

    def test_random_iv_produces_different_ciphertexts(self):
        key = b"samekey"
        plaintext = b"same plaintext"
        ct1 = AESEncryptOFB(key, plaintext)
        ct2 = AESEncryptOFB(key, plaintext)
        # Each call uses os.urandom(16) so ciphertexts must differ
        assert ct1 != ct2

    def test_output_includes_iv_prefix(self):
        key = b"k" * 16
        plaintext = b"data"
        ciphertext = AESEncryptOFB(key, plaintext)
        # First 16 bytes are IV, rest is ciphertext
        assert len(ciphertext) >= 16

    def test_long_payload(self):
        key = b"longpayloadkey!!"
        plaintext = os.urandom(4096)
        ciphertext = AESEncryptOFB(key, plaintext)
        result = AESDecryptOFB(key, ciphertext)
        assert result == plaintext


class TestRC4:

    def test_roundtrip(self):
        key = b"rc4key"
        plaintext = b"encrypt me"
        ciphertext = RC4(key, plaintext)
        assert ciphertext != plaintext
        result = RC4(key, ciphertext)
        assert result == plaintext

    def test_str_inputs(self):
        key = "strkey"
        plaintext = "strplaintext"
        ciphertext = RC4(key, plaintext)
        result = RC4(key, ciphertext)
        assert result == plaintext.encode('utf-8')

    def test_empty_plaintext(self):
        result = RC4(b"key", b"")
        assert result == b""

    def test_returns_bytes(self):
        result = RC4(b"k", b"data")
        assert isinstance(result, bytes)


class TestHMAC:

    def test_generate_returns_bytes(self):
        digest = GenerateHMAC(b"data", b"key")
        assert isinstance(digest, bytes)
        assert len(digest) == 32  # SHA-256

    def test_verify_correct(self):
        data = b"important payload"
        key = b"hmackey"
        digest = GenerateHMAC(data, key)
        assert VerifyHMAC(data, digest, key) is True

    def test_verify_wrong_data(self):
        key = b"hmackey"
        digest = GenerateHMAC(b"original", key)
        assert VerifyHMAC(b"tampered", digest, key) is False

    def test_verify_wrong_key(self):
        data = b"payload"
        digest = GenerateHMAC(data, b"correctkey")
        assert VerifyHMAC(data, digest, b"wrongkey") is False
