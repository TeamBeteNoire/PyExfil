import struct
from os import path


def _is_slice_in_list(s, l):
    len_s = len(s)
    return any(s == l[i:len_s + i] for i in range(len(l) - len_s + 1))


def _split_every_n(data, n):
    return [data[i:i + n] for i in range(0, len(data), n)]


def _icmp_checksum(data):
    if isinstance(data, str):
        data = data.encode('latin-1')
    s = 0
    n = len(data) % 2
    for i in range(0, len(data) - n, 2):
        s += (data[i] << 8) + data[i + 1]
    if n:
        s += data[-1] << 8
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


def inet_aton(packed):
    try:
        quads = struct.unpack('BBBB', packed)
        return '.'.join(str(q) for q in quads)
    except (struct.error, TypeError):
        return False


def does_file_exist(file_path):
    return path.exists(file_path) and path.isfile(file_path)
