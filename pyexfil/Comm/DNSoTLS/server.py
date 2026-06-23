#!/usr/bin/env python3

import sys
import ssl
import random
import socket

from pyexfil.includes.base import CommModule

try:
    from pyexfil.Comm.DNSoTLS.constants import (
        LOCAL_HOST,
        DNS_OVER_TLS_PORT,
        MAX_CLIENTS,
        CERT_FILE,
        CHUNK_SIZE,
    )
except ImportError:
    from constants import LOCAL_HOST, DNS_OVER_TLS_PORT, MAX_CLIENTS, CERT_FILE, CHUNK_SIZE

context = None


def AutomateMe(data, sslSocket):
    """
    This is where you automate me.
    :param data: data that came in [bytes]
    :param sslSocket: Client SSL Socket Object [ssl wrapper socket object]
    :return: None
    """
    return


def StartServer(server_name=LOCAL_HOST, port=DNS_OVER_TLS_PORT,
                clients=MAX_CLIENTS, certfile=CERT_FILE, keep_ratio=True,
                callback=None, stop_event=None):
    """
    Start the server.
    :param server_name: IP of server [str]
    :param port:        Port of server [int]
    :param clients:     Max clients [int]
    :param certfile:    Path to certificate [str]
    :param keep_ratio:  Mirror upload:download ratio [bool]
    :param callback:    Called with (data, meta) for each received chunk.
    :param stop_event:  threading.Event signalling graceful stop.
    :return: bool
    """
    global context

    context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)

    try:
        context.load_cert_chain(certfile=certfile)
    except Exception as e:
        sys.stderr.write(
            "[!]\tError opening the certificate file '%s'.\n%s.\n" % (certfile, str(e))
        )
        return False

    try:
        bind_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        bind_sock.bind((server_name, port))
        bind_sock.listen(clients)
        bind_sock.settimeout(1.0)
    except Exception as e:
        sys.stderr.write("[!]\tError listening on socket.\n%s.\n" % str(e))
        return False

    while True:
        if stop_event is not None and stop_event.is_set():
            break
        try:
            newsocket, fromaddr = bind_sock.accept()
            sslsoc = context.wrap_socket(newsocket, server_side=True)
            data = sslsoc.read()
            AutomateMe(data=data, sslSocket=sslsoc)
            if keep_ratio:
                sslsoc.send(
                    str(random.getrandbits(random.randint(8, CHUNK_SIZE))).encode("utf-8")
                )
            ip, conn_port = newsocket.getpeername()
            sys.stdout.write("\t[%s:%s] '%s'.\n" % (ip, conn_port, data))
            if callback is not None:
                callback(data, {"src": (ip, conn_port)})
        except socket.timeout:
            continue
        except KeyboardInterrupt:
            sys.stdout.write("\n[!]\tGot a CTRL+C. Exiting now.\n")
            return True
        except socket.error as e:
            sys.stderr.write(
                "Caught an unknown socket exception. Making sure to kill the socket.\n"
            )
            sys.stderr.write("%s.\n" % str(e))
            bind_sock.close()
            return False
    return True


class DNSoTLSServer(CommModule):

    MODULE_NAME = "DNSoTLSServer"
    PROTOCOL    = "dns-over-tls"

    def __init__(self, host=LOCAL_HOST, port=DNS_OVER_TLS_PORT,
                 certfile=CERT_FILE, max_clients=MAX_CLIENTS,
                 keep_ratio=True, verbose=False):
        """
        :param host:        Bind address [str]
        :param port:        TLS listen port [int]
        :param certfile:    Path to TLS certificate [str]
        :param max_clients: Max simultaneous clients [int]
        :param keep_ratio:  Mirror upload:download ratio [bool]
        """
        super().__init__(enc_key="", on_message=None, verbose=verbose)
        self.host        = host
        self.port        = port
        self.certfile    = certfile
        self.max_clients = max_clients
        self.keep_ratio  = keep_ratio

    def _send_impl(self, data, **kwargs):
        raise NotImplementedError(
            "DNSoTLSServer is a receive-only module. Use DNSoTLSComm to send."
        )

    def _broadcast_impl(self, data, **kwargs):
        raise NotImplementedError(
            "DNSoTLSServer is a receive-only module."
        )

    def _listen_impl(self, callback, **kwargs):
        StartServer(
            server_name=self.host,
            port=self.port,
            clients=self.max_clients,
            certfile=self.certfile,
            keep_ratio=self.keep_ratio,
            callback=callback,
            stop_event=self._stop_event,
        )


if __name__ == "__main__":
    StartServer()
