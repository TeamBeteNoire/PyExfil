#!/usr/bin/env python3
"""
Binary-offset steganography: hide data by adding bit-values to image pixels.

Usage:
    from pyexfil.Stega.binoffset.binoffset import BinOffsetStega

    stega = BinOffsetStega()

    # Prepare a clean base image (cap pixel values so encoding won't overflow)
    stega.prepare_base("photo.jpg", "base.jpg")

    # Encode
    stega.encode("base.jpg", "/etc/passwd", "stego.jpg")

    # Decode
    stega.decode("base.jpg", "stego.jpg", "recovered.txt")

    # Also accessible via the generic interface:
    stega.send(["base.jpg", "/etc/passwd", "stego.jpg"])
    stega.receive(carrier="base.jpg", stego="stego.jpg", output="recovered.txt")
"""

import sys
import zlib
import binascii

import numpy as np
from PIL import Image

from pyexfil.includes.base import StegaModule

BUFF_CHAR = 5
PIXEL_MAX = 255


def _str2bin(raw_data: bytes) -> str:
    return bin(int(binascii.hexlify(raw_data), 16))[2:]


def _file_to_rgb_offsets(file_name: str):
    """Compress file and convert to list of [R,G,B] bit-triplets."""
    try:
        with open(file_name, "rb") as f:
            raw = f.read()
    except IOError as e:
        sys.stderr.write("[BinOffset] Cannot open '%s': %s\n" % (file_name, e))
        return False

    compressed = zlib.compress(raw)
    bin_data = _str2bin(compressed)
    triplets = [bin_data[i:i + 3] for i in range(0, len(bin_data), 3)]

    result = []
    for t in triplets:
        try:
            result.append([int(t[0]), int(t[1]), int(t[2])])
        except IndexError:
            if len(t) >= 2:
                result.append([int(t[0]), int(t[1]), BUFF_CHAR])
            else:
                result.append([int(t[0]), BUFF_CHAR, BUFF_CHAR])
    return result


def _open_image(image_path: str):
    img = Image.open(image_path)
    w, h = img.size
    return img, w, h, w * h


def _image_to_pixels(img):
    return list(img.getdata())


class BinOffsetStega(StegaModule):
    """
    Steganography by adding binary-encoded payload bits to pixel RGB channels.
    """

    MODULE_NAME = "BinOffset"
    PROTOCOL    = "stega/pixel-offset"

    def prepare_base(self, image_path: str, output_path: str) -> bool:
        """
        Cap all pixel channels to PIXEL_MAX - BUFF_CHAR so encoding won't overflow.
        Call this once on a cover image before using it with encode().
        """
        try:
            img, w, h, _ = _open_image(image_path)
            pixels = _image_to_pixels(img)
            cap = PIXEL_MAX - BUFF_CHAR
            final = []
            for px in pixels:
                r = min(px[0], cap)
                g = min(px[1], cap)
                b = min(px[2], cap)
                final.append((r, g, b))
            out = Image.new(img.mode, (w, h))
            out.putdata(final)
            out.save(output_path)
            sys.stdout.write("[BinOffset] Base image saved to '%s'.\n" % output_path)
            return True
        except Exception as e:
            sys.stderr.write("[BinOffset] prepare_base failed: %s\n" % e)
            return False

    # ------------------------------------------------------------------
    # StegaModule hooks
    # ------------------------------------------------------------------

    def _encode_impl(self, carrier: str, payload: str, output: str, **kwargs) -> bool:
        img, w, h, total_px = _open_image(carrier)
        pixels = _image_to_pixels(img)
        offsets = _file_to_rgb_offsets(payload)
        if offsets is False:
            return False

        if len(offsets) >= total_px:
            sys.stderr.write(
                "[BinOffset] Payload too large: %d bits vs %d pixels.\n"
                % (len(offsets), total_px)
            )
            return False

        final = []
        for i, (dr, dg, db) in enumerate(offsets):
            r = int(pixels[i][0]) + dr
            g = int(pixels[i][1]) + dg
            b = int(pixels[i][2]) + db
            final.append((r, g, b))

        # Padding pixels
        for i in range(len(offsets), total_px):
            r = int(pixels[i][0]) + BUFF_CHAR
            g = int(pixels[i][1]) + BUFF_CHAR
            b = int(pixels[i][2]) + BUFF_CHAR
            final.append((r, g, b))

        out_img = Image.new(img.mode, (w, h))
        out_img.putdata(final)
        out_img.save(output)
        sys.stdout.write("[BinOffset] Stego image saved to '%s'.\n" % output)
        return True

    def _decode_impl(self, carrier: str, stego: str, output: str, **kwargs) -> bool:
        img_orig, w, h, total_px = _open_image(carrier)
        orig_px = _image_to_pixels(img_orig)

        img_stego, sw, sh, stego_total = _open_image(stego)
        stego_px = _image_to_pixels(img_stego)

        if total_px != stego_total:
            sys.stderr.write(
                "[BinOffset] Size mismatch: carrier %dx%d vs stego %dx%d.\n"
                % (w, h, sw, sh)
            )
            return False

        bin_str = ""
        for i in range(total_px):
            try:
                or_, og, ob = orig_px[i][:3]
                sr, sg, sb  = stego_px[i][:3]
            except (ValueError, IndexError):
                continue
            bin_str += str(sr - or_) + str(sg - og) + str(sb - ob)

        # Strip padding marker
        bin_str = bin_str.replace(str(BUFF_CHAR), "")
        # Keep only valid binary digits
        bin_str = "".join(c for c in bin_str if c in "01")

        try:
            hex_str  = "%x" % int("0b" + bin_str, 2)
            raw      = binascii.unhexlify(hex_str)
            decoded  = zlib.decompress(raw)
        except Exception as e:
            sys.stderr.write("[BinOffset] Decode failed: %s\n" % e)
            return False

        with open(output, "wb") as f:
            f.write(decoded)
        sys.stdout.write("[BinOffset] Recovered %d bytes → '%s'.\n" % (len(decoded), output))
        return True
