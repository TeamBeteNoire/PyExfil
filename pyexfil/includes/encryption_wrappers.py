import os
import hmac
import base64
import hashlib

from Crypto.Cipher import AES

_MODE = AES.MODE_OFB
_DEFAULT_PASSWORD = base64.b64decode(b'VEhBVElTQURFQURQQVJST1Qh')


def _pad_key(key):
    if isinstance(key, str):
        key = key.encode('utf-8')
    return key + b'\x00' * (32 - len(key))


def GenerateHMAC(data, key=_DEFAULT_PASSWORD):
    if isinstance(key, str):
        key = key.encode('utf-8')
    return hmac.new(key, data, hashlib.sha256).digest()


def VerifyHMAC(data, expected_hmac, key=_DEFAULT_PASSWORD):
    return hmac.compare_digest(GenerateHMAC(data, key), expected_hmac)


def AESEncryptOFB(key, text, iv=None):
    if iv is None:
        iv = os.urandom(16)
    padded_key = _pad_key(key)
    pad_len = (-len(text)) % 16
    padded_text = text + b'\x00' * pad_len
    cipher = AES.new(padded_key, _MODE, iv)
    return iv + cipher.encrypt(padded_text)


def AESDecryptOFB(key, data, unpad=True):
    iv, ciphertext = data[:16], data[16:]
    padded_key = _pad_key(key)
    cipher = AES.new(padded_key, _MODE, iv)
    plain = cipher.decrypt(ciphertext)
    if unpad:
        plain = plain.rstrip(b'\x00')
    return plain


def RC4(key, plaintext):
    if isinstance(key, str):
        key = key.encode('utf-8')
    if isinstance(plaintext, str):
        plaintext = plaintext.encode('utf-8')
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    i = j = 0
    out = bytearray()
    for byte in plaintext:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        out.append(byte ^ S[(S[i] + S[j]) % 256])
    return bytes(out)
