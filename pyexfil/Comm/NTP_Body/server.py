#!/usr/bin/env python3

import logging
import socket
import threading

from pyexfil.includes.base import CommModule
from pyexfil.Comm.NTP_Body.ntp_consts import NTP_PORT, KEY, RECV_BUFFER, _buildNTP
from pyexfil.includes.encryption_wrappers import AESDecryptOFB, AESEncryptOFB


class Broker(CommModule):

    MODULE_NAME = "NTPBodyBroker"
    PROTOCOL    = "ntp-body"

    def __init__(self, host="", port=NTP_PORT, enc_key=KEY,
                 on_message=None, verbose=False):
        """
        :param host:       Server bind address [str]
        :param port:       NTP port [int]
        :param enc_key:    AES-OFB key [bytes]
        :param on_message: Callback(data, meta) called on each decrypted message.
        """
        super().__init__(enc_key="", on_message=on_message, verbose=verbose)
        # enc_key may be raw bytes from ntp_consts; store separately for wrappers
        self._raw_key    = enc_key
        self.host        = host
        self.port        = port
        self.sock        = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((host, port))
        self.clients_list = []
        logging.info("NTPBodyBroker initialised on %s:%s", host, port)

    # ------------------------------------------------------------------
    # Legacy protocol helpers (logic unchanged)
    # ------------------------------------------------------------------

    def talkToClient(self, ip, data=None):
        """
        Send an AES-encrypted NTP response to ip.
        :param ip:   (host, port) tuple
        :param data: bytes payload to embed; defaults to b"OK"
        """
        if data is None:
            data = b"OK"
        logging.info("Sending to %s", ip)
        if isinstance(data, str):
            data = data.encode("utf-8")
        d  = _buildNTP()
        d += AESEncryptOFB(key=self._raw_key, text=data)
        self.sock.sendto(d, ip)

    def listen_clients(self):
        while not self._stop_event.is_set():
            self.sock.settimeout(1.0)
            try:
                msg, client = self.sock.recvfrom(RECV_BUFFER)
            except socket.timeout:
                continue
            logging.info("Received data from client %s.", str(client))
            # NTP header is 16 bytes; AES payload (with prepended IV) follows
            ntp_payload = msg[16:]
            if len(ntp_payload) >= 16:
                decData = AESDecryptOFB(key=self._raw_key, data=ntp_payload)
            else:
                decData = ntp_payload
            logging.info("Decrypted message reads: %s.", decData)
            t = threading.Thread(target=self.talkToClient, args=(client,))
            t.start()

    # ------------------------------------------------------------------
    # CommModule abstract implementations
    # ------------------------------------------------------------------

    def _send_impl(self, data, **kwargs):
        ip = kwargs.get("ip")
        if ip is None:
            logging.error("NTPBodyBroker._send_impl requires 'ip' kwarg.")
            return False
        self.talkToClient(ip, data)
        return True

    def _broadcast_impl(self, data, **kwargs):
        return self._send_impl(data, **kwargs)

    def _listen_impl(self, callback, **kwargs):
        while not self._stop_event.is_set():
            self.sock.settimeout(1.0)
            try:
                msg, client = self.sock.recvfrom(RECV_BUFFER)
            except socket.timeout:
                continue
            logging.info("Received data from client %s.", str(client))
            ntp_payload = msg[16:]
            if len(ntp_payload) >= 16:
                plaintext = AESDecryptOFB(key=self._raw_key, data=ntp_payload)
            else:
                plaintext = ntp_payload
            callback(plaintext, {"client": client})
            t = threading.Thread(target=self.talkToClient, args=(client,))
            t.start()


if __name__ == "__main__":
    logging.getLogger().setLevel(logging.DEBUG)
    b = Broker()
    b.listen_clients()
