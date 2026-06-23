#!/usr/bin/env python3

import logging
import socket
import threading

from pyexfil.includes.base import CommModule
from pyexfil.includes.encryption_wrappers import (
    AESDecryptOFB,
    AESEncryptOFB,
    _DEFAULT_PASSWORD,
)

logging.getLogger().setLevel(logging.DEBUG)


def testCallBack(src, decryptedMsg):
    print("\n[%s:%s](incoming)\t'%s'.\n" % (src[0], src[1], decryptedMsg))


class Broker(CommModule):

    MODULE_NAME = "JetDirectBroker"
    PROTOCOL    = "jetdirect-udp"

    def __init__(self, client, host="127.0.0.1", port=9100,
                 key=_DEFAULT_PASSWORD, retFunc=testCallBack,
                 on_message=None, verbose=False):
        """
        :param client: Client's IP to send to [str]
        :param host:   Bind address for listener [str]
        :param port:   UDP port [int]
        :param key:    AES-OFB key [bytes or str]
        :param retFunc: Legacy callback(src, plaintext). Kept for back-compat.
        :param on_message: CommModule callback(data, meta).
        """
        super().__init__(enc_key=key if isinstance(key, str) else "", on_message=on_message, verbose=verbose)
        # Store the raw key for the AES wrappers (may be bytes)
        self._raw_key = key
        self.retFunc  = retFunc
        self.client   = client
        self.port     = port
        self.host     = host
        logging.info("Now listening for %s/udp Broadcasts.", port)
        logging.info("Hit 'exit' to quit.")

    # ------------------------------------------------------------------
    # Internal helpers (legacy protocol logic — unchanged)
    # ------------------------------------------------------------------

    def parse_message(self, src, data):
        decPayload = AESDecryptOFB(key=self._raw_key, data=data)
        if self.retFunc is not None:
            self.retFunc(src, decPayload)
        return decPayload

    def listen_clients(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        logging.info("Listening on UDP %s:%s", self.host, self.port)
        s.bind((self.host, self.port))
        while not self._stop_event.is_set():
            s.settimeout(1.0)
            try:
                (data, addr) = s.recvfrom(128 * 1024)
                self.parse_message(addr, data)
            except socket.timeout:
                continue

    def broadcast_message(self, message):
        if isinstance(message, str):
            message = message.encode("utf-8")
        msg = AESEncryptOFB(key=self._raw_key, text=message)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(msg, (self.client, self.port))

    # ------------------------------------------------------------------
    # CommModule abstract implementations
    # ------------------------------------------------------------------

    def _broadcast_impl(self, data, **kwargs):
        self.broadcast_message(data)
        return True

    def _send_impl(self, data, **kwargs):
        return self._broadcast_impl(data)

    def _listen_impl(self, callback, **kwargs):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        logging.info("Listening on UDP %s:%s", self.host, self.port)
        s.bind((self.host, self.port))
        while not self._stop_event.is_set():
            s.settimeout(1.0)
            try:
                (data, addr) = s.recvfrom(128 * 1024)
                plaintext = AESDecryptOFB(key=self._raw_key, data=data)
                callback(plaintext, {"src": addr})
            except socket.timeout:
                continue


if __name__ == '__main__':
    b = Broker(client="127.0.0.1")
    t = threading.Thread(target=b.listen_clients, daemon=True)
    t.start()
    while True:
        send_me = input("message> ")
        msg = send_me.strip()
        if msg == "":
            continue
        elif msg == "exit":
            logging.info("Got exit message.\n")
            exit()
        else:
            b.broadcast_message(msg)
            logging.info("[%s] out the door.", len(msg))
