#!/usr/bin/env python3

import os
import sys
import zlib
import time
import random
import struct
import base64
import hashlib

from pyexfil.includes.encryption_wrappers import RC4

DEFAULT_KEY             = "ShutTheFuckUpDonnie!"
DEFAULT_MAX_PACKET_SIZE = 65000

BINARY_DELIMITER = b"\x00\x00\xFF\xFF"
ASCII_DELIMITER  = b"<AAA\\>"


def _splitString(data, length):
    if not isinstance(length, int):
        sys.stderr.write("'length' parameter must be an int.\n")
        return False
    if not isinstance(data, (str, bytes)):
        sys.stderr.write("'data' parameter must be str or bytes.\n")
        return False
    return [data[i:i + length] for i in range(0, len(data), length)]


def DecodePacket(packet_data, enc_key=DEFAULT_KEY, b64_flag=False):
    ret = {}
    encryption = enc_key != ""

    if b64_flag:
        data = base64.b64decode(packet_data)
    else:
        data = packet_data if isinstance(packet_data, bytes) else packet_data.encode('latin-1')

    if encryption:
        if ASCII_DELIMITER in data or BINARY_DELIMITER in data:
            delm = ASCII_DELIMITER if ASCII_DELIMITER in data else BINARY_DELIMITER
            splitData = data.split(delm)
            ret['initFlag'] = True
            ret['fileData'] = {
                'FileName':     splitData[0].decode('utf-8', errors='replace'),
                'TotalPackets': splitData[2].decode('utf-8', errors='replace'),
                'SequenceID':   splitData[3].decode('utf-8', errors='replace'),
                'MD5':          splitData[4].decode('utf-8', errors='replace'),
            }
            ret['packetNumber'] = splitData[1].decode('utf-8', errors='replace')
            return ret

        try:
            key_bytes = enc_key.encode('utf-8') if isinstance(enc_key, str) else enc_key
            data = RC4(key_bytes, data)
        except (ValueError, TypeError) as e:
            sys.stderr.write("Data does not decrypt using the key you've provided.\n%s\n" % e)
            return False

    delm = ASCII_DELIMITER if ASCII_DELIMITER in data else BINARY_DELIMITER
    splitData = data.split(delm)

    if len(splitData) == 5:
        ret['initFlag'] = True
        ret['fileData'] = {
            'FileName':     splitData[0].decode('utf-8', errors='replace'),
            'TotalPackets': splitData[2].decode('utf-8', errors='replace'),
            'SequenceID':   splitData[3].decode('utf-8', errors='replace'),
            'MD5':          splitData[4].decode('utf-8', errors='replace'),
        }
        ret['packetNumber'] = splitData[1].decode('utf-8', errors='replace')
        return ret

    elif len(splitData) == 3:
        ret['initFlag']    = False
        ret['SequenceID']  = splitData[0].decode('utf-8', errors='replace')
        ret['packetNumber']= splitData[1].decode('utf-8', errors='replace')
        ret['Data']        = splitData[2]
        return ret

    else:
        sys.stderr.write("Packet split into %s chunks which are unknown.\n" % len(splitData))
        return False


def PrepFile(file_path, kind='binary', max_size=DEFAULT_MAX_PACKET_SIZE, enc_key=DEFAULT_KEY):
    ret = {}
    if kind not in ('binary', 'ascii'):
        sys.stderr.write("Parameter 'kind' must be binary/ascii.\n")
        return False

    delm = ASCII_DELIMITER if kind == 'ascii' else BINARY_DELIMITER

    try:
        with open(file_path, 'rb') as f:
            data = f.read()
    except IOError as e:
        sys.stderr.write("Error opening file '%s': %s\n" % (file_path, e))
        return False

    hash_raw  = hashlib.md5(data).hexdigest()
    compData  = zlib.compress(data)
    hash_comp = hashlib.md5(compData).hexdigest()

    ret['EncryptionFlag'] = enc_key != ""
    if ret['EncryptionFlag']:
        ret['Key'] = enc_key

    ret['FilePath']       = file_path
    ret['ChunksSize']     = max_size
    ret['FileName']       = os.path.basename(file_path)
    ret['RawHash']        = hash_raw
    ret['CompressedHash'] = hash_comp

    data_for_packets = base64.b64encode(compData) if kind == 'ascii' else compData
    ret['CompressedSize'] = len(data_for_packets)
    ret['RawSize']        = len(data)

    packetsData        = _splitString(data_for_packets, max_size)
    ret['PacketsCount']    = len(packetsData) + 1
    ret['FileSequenceID']  = random.randint(1024, 4096)
    ret['Packets']         = []

    fname   = ret['FileName'].encode('utf-8')
    pcount  = str(len(packetsData) + 1).encode('utf-8')
    seqID   = str(ret['FileSequenceID']).encode('utf-8')
    ha      = hash_raw.encode('utf-8')

    init_pkt = fname + delm + b"1" + delm + pcount + delm + seqID + delm + ha
    if enc_key:
        key_bytes = enc_key.encode('utf-8') if isinstance(enc_key, str) else enc_key
        init_pkt = RC4(key_bytes, init_pkt)
    if kind == 'ascii':
        init_pkt = base64.b64encode(init_pkt)
    ret['Packets'].append(init_pkt)

    key_bytes = enc_key.encode('utf-8') if isinstance(enc_key, str) else enc_key
    for i, chunk in enumerate(packetsData, start=2):
        pkt = seqID + delm + str(i).encode('utf-8') + delm + chunk
        if enc_key:
            pkt = RC4(key_bytes, pkt)
        if kind == 'ascii':
            pkt = base64.b64encode(pkt)
        ret['Packets'].append(pkt)

    return ret


def PrepString(data, max_size=DEFAULT_MAX_PACKET_SIZE, enc_key=DEFAULT_KEY, compress=True):
    if isinstance(data, str):
        data = data.encode('utf-8')
    if isinstance(enc_key, str):
        enc_key = enc_key.encode('utf-8')

    hash_raw = hashlib.md5(data).hexdigest()
    ret = {
        'EncryptionFlag': enc_key != b"",
        'FilePath':  None,
        'FileName':  None,
        'RawHash':   hash_raw,
        'RawSize':   len(data),
    }
    if ret['EncryptionFlag']:
        ret['Key'] = enc_key

    processed = RC4(enc_key, data) if enc_key else data
    if compress:
        processed = base64.b85encode(zlib.compress(processed))

    ret['CompressedHash'] = hashlib.md5(processed).hexdigest()
    ret['CompressedSize'] = len(processed)

    packetsData           = _splitString(processed, max_size)
    ret['PacketsCount']   = len(packetsData) + 1
    ret['FileSequenceID'] = random.randint(1024, 4096)
    ret['Packets']        = packetsData
    return ret


def RebuildFile(packets_data):
    if not isinstance(packets_data, list):
        sys.stderr.write("'packets_data' must be a list of DecodePacket outputs.\n")
        return False

    init_pkt = None
    for pkt in packets_data:
        if not isinstance(pkt, dict):
            sys.stderr.write("All elements must be dicts.\n")
            return False
        if pkt.get('initFlag') is True:
            init_pkt = pkt

    if init_pkt is None:
        sys.stderr.write("No init packet was found.\n")
        return False

    md5       = init_pkt['fileData']['MD5']
    seq       = int(init_pkt['fileData']['SequenceID'])
    pkt_count = int(init_pkt['fileData']['TotalPackets'])
    fname     = init_pkt['fileData']['FileName']

    ret = {
        'FileName': fname,
        'Packets':  pkt_count,
        'MD5':      md5,
        'Sequence': seq,
        'Success':  False,
    }

    raw_data = b""
    for i in range(2, pkt_count + 1):
        found = False
        for pkt in packets_data:
            try:
                if int(pkt['SequenceID']) == seq and int(pkt['packetNumber']) == i:
                    chunk = pkt['Data']
                    raw_data += chunk if isinstance(chunk, bytes) else chunk.encode('latin-1')
                    found = True
                    break
            except (KeyError, ValueError):
                pass
        if not found:
            sys.stderr.write("Packet %s is missing.\n" % i)
            return False

    try:
        decoded = zlib.decompress(raw_data)
        ret['Data']       = decoded
        ret['DataLength'] = len(decoded)
        summ = hashlib.md5(decoded).hexdigest()
        ret['Success'] = True
        ret['Info'] = "Decoded and hashes matched!" if summ == md5 else "Decoded but hashes do not match."
    except zlib.error:
        ret['Data']       = raw_data
        ret['DataLength'] = len(raw_data)
        ret['Info']       = "Unable to decompress data"

    return ret


if __name__ == "__main__":
    sys.stderr.write("Not a standalone module.\n")
    sys.exit(1)
