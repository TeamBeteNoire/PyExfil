#!/usr/bin/env python3
"""
PyExfil base class hierarchy.

PyExfilModule
├── NetworkModule   – socket-based exfiltration (DNS, ICMP, HTTP, FTP…)
├── CommModule      – bidirectional C2 over network channels (ARP, NTP, MDNS…)
├── PhysicalModule  – one-way physical-channel output (audio, QR, ultrasonic…)
└── StegaModule     – file-in / file-out steganography (PNG, binoffset, braille…)

Each subclass wires its transport into send/broadcast and listen/receive.
"""

import abc
import logging
import threading
from typing import Any, Callable, Optional

logger = logging.getLogger(__name__)


class PyExfilModule(abc.ABC):
    """
    Abstract root for every PyExfil module.

    Subclasses must implement:
        _send_impl(data, **kwargs)
        _listen_impl(**kwargs)

    Optionally override:
        _broadcast_impl(data, **kwargs)   – defaults to _send_impl
        _receive_impl(**kwargs)            – defaults to _listen_impl
    """

    #: Human-readable name shown in logs and repr
    MODULE_NAME: str = "PyExfilModule"
    #: Which pillar this belongs to ('network', 'comm', 'physical', 'stega')
    MODULE_TYPE: str = "base"
    #: Protocol or channel used (set by concrete module)
    PROTOCOL: str = "generic"

    def __init__(self, enc_key: str = "", verbose: bool = False):
        self.enc_key = enc_key
        self.verbose = verbose
        self._stop_event = threading.Event()
        self._listener_thread: Optional[threading.Thread] = None
        if verbose:
            logging.basicConfig(level=logging.DEBUG)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def send(self, data: Any, **kwargs) -> bool:
        """
        Send data through this module's channel.

        Args:
            data: Bytes, file path string, or module-specific payload.
            **kwargs: Module-specific options (host, port, delay…).

        Returns:
            True on success, False on failure.
        """
        try:
            return self._send_impl(data, **kwargs)
        except Exception as e:
            logger.error("[%s] send() failed: %s", self.MODULE_NAME, e)
            return False

    def broadcast(self, data: Any, **kwargs) -> bool:
        """
        Broadcast data (one-to-many). Defaults to send() for modules where
        the distinction does not apply.
        """
        try:
            return self._broadcast_impl(data, **kwargs)
        except Exception as e:
            logger.error("[%s] broadcast() failed: %s", self.MODULE_NAME, e)
            return False

    def listen(
        self,
        callback: Optional[Callable] = None,
        blocking: bool = True,
        **kwargs,
    ) -> Optional[threading.Thread]:
        """
        Start the receive/server side.

        Args:
            callback: Called with each received payload. Signature:
                      callback(data: bytes, meta: dict) -> None
                      If None, data is logged at INFO level.
            blocking: If True, blocks the calling thread (runs inline).
                      If False, runs in a daemon thread and returns it.
            **kwargs: Module-specific options (host, port, save_path…).

        Returns:
            The Thread object when blocking=False, else None.
        """
        self._stop_event.clear()
        cb = callback or self._default_callback

        if blocking:
            self._listen_impl(callback=cb, **kwargs)
            return None

        t = threading.Thread(
            target=self._listen_impl,
            kwargs={"callback": cb, **kwargs},
            daemon=True,
            name="%s-listener" % self.MODULE_NAME,
        )
        self._listener_thread = t
        t.start()
        return t

    def receive(self, **kwargs) -> Any:
        """
        Synchronous single-shot receive. Blocks until one payload arrives.
        Modules that are inherently stream-based should override this.
        """
        return self._receive_impl(**kwargs)

    def stop(self) -> None:
        """Signal the listener to stop gracefully."""
        self._stop_event.set()
        if self._listener_thread and self._listener_thread.is_alive():
            self._listener_thread.join(timeout=5)

    # ------------------------------------------------------------------
    # Abstract transport hooks — implement in concrete modules
    # ------------------------------------------------------------------

    @abc.abstractmethod
    def _send_impl(self, data: Any, **kwargs) -> bool:
        """Wire the actual send transport here."""

    @abc.abstractmethod
    def _listen_impl(self, callback: Callable, **kwargs) -> None:
        """Wire the actual listen/server loop here."""

    # ------------------------------------------------------------------
    # Default implementations (override when needed)
    # ------------------------------------------------------------------

    def _broadcast_impl(self, data: Any, **kwargs) -> bool:
        """Default: broadcast == send. Override for true multicast."""
        return self._send_impl(data, **kwargs)

    def _receive_impl(self, **kwargs) -> Any:
        """Default: not supported for stream-based modules."""
        raise NotImplementedError(
            "%s does not support synchronous receive(). Use listen() instead."
            % self.MODULE_NAME
        )

    def _default_callback(self, data: bytes, meta: dict) -> None:
        logger.info("[%s] received %d bytes | meta=%s", self.MODULE_NAME, len(data), meta)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def __repr__(self) -> str:
        return "<%s protocol=%s enc=%s>" % (
            self.MODULE_NAME, self.PROTOCOL, bool(self.enc_key)
        )


# ---------------------------------------------------------------------------
# NetworkModule
# ---------------------------------------------------------------------------

class NetworkModule(PyExfilModule):
    """
    Base for socket/protocol-based exfiltration (DNS, ICMP, HTTP, FTP, QUIC…).

    Adds:
        - host / port as first-class constructor params
        - PrepFile / DecodePacket plumbing from includes.prepare
        - _packet_delay: inter-packet sleep
    """

    MODULE_TYPE = "network"

    def __init__(
        self,
        host: str,
        port: int,
        enc_key: str = "",
        packet_delay: float = 0.05,
        max_packet_size: int = 512,
        verbose: bool = False,
    ):
        super().__init__(enc_key=enc_key, verbose=verbose)
        self.host = host
        self.port = port
        self.packet_delay = packet_delay
        self.max_packet_size = max_packet_size

    def _send_impl(self, data: Any, **kwargs) -> bool:
        raise NotImplementedError("NetworkModule subclasses must implement _send_impl")

    def _listen_impl(self, callback: Callable, **kwargs) -> None:
        raise NotImplementedError("NetworkModule subclasses must implement _listen_impl")


# ---------------------------------------------------------------------------
# CommModule
# ---------------------------------------------------------------------------

class CommModule(PyExfilModule):
    """
    Base for bidirectional C2 communications (ARP, NTP body, MDNS, AllJoyn…).

    Adds:
        - symmetric broadcast/listen pattern
        - encryption key is required (defaults to PyExfil default)
        - on_message callback wired into listen()
    """

    MODULE_TYPE = "comm"

    def __init__(
        self,
        enc_key: str = "",
        on_message: Optional[Callable] = None,
        verbose: bool = False,
    ):
        super().__init__(enc_key=enc_key, verbose=verbose)
        # on_message is the application-level callback; stored for subclasses
        self.on_message = on_message

    def _send_impl(self, data: Any, **kwargs) -> bool:
        raise NotImplementedError("CommModule subclasses must implement _send_impl")

    def _broadcast_impl(self, data: Any, **kwargs) -> bool:
        """Comms modules should broadcast by default — override with real impl."""
        raise NotImplementedError("CommModule subclasses must implement _broadcast_impl")

    def _listen_impl(self, callback: Callable, **kwargs) -> None:
        raise NotImplementedError("CommModule subclasses must implement _listen_impl")


# ---------------------------------------------------------------------------
# PhysicalModule
# ---------------------------------------------------------------------------

class PhysicalModule(PyExfilModule):
    """
    Base for physical-channel exfiltration (audio, QR, ultrasonic, 3.5mm jack…).

    Physical channels are generally one-way (send-only). receive() raises
    NotImplementedError by default; subclasses that can read back (e.g. a
    microphone listening for ultrasonic) override _receive_impl.
    """

    MODULE_TYPE = "physical"

    def __init__(self, verbose: bool = False):
        super().__init__(enc_key="", verbose=verbose)

    def _send_impl(self, data: Any, **kwargs) -> bool:
        raise NotImplementedError("PhysicalModule subclasses must implement _send_impl")

    def _listen_impl(self, callback: Callable, **kwargs) -> None:
        raise NotImplementedError(
            "%s does not support network-style listen(). "
            "Use receive() if the channel supports it." % self.MODULE_NAME
        )

    def _receive_impl(self, **kwargs) -> Any:
        raise NotImplementedError(
            "%s does not support receive(). "
            "This is a send-only physical channel." % self.MODULE_NAME
        )


# ---------------------------------------------------------------------------
# StegaModule
# ---------------------------------------------------------------------------

class StegaModule(PyExfilModule):
    """
    Base for file-based steganography (PNG, binoffset, braille, DataMatrix…).

    Renames the interface to match steganography vocabulary:
        encode(carrier, payload, output)  → hides payload in carrier → output file
        decode(carrier, stego, output)    → extracts payload from stego file

    send() / listen() are mapped to encode() / decode() so the top-level
    interface stays uniform. Direct socket send/listen are not applicable.
    """

    MODULE_TYPE = "stega"

    def __init__(self, verbose: bool = False):
        super().__init__(enc_key="", verbose=verbose)

    # --- Stega-specific API ---

    def encode(self, carrier: str, payload: str, output: str, **kwargs) -> bool:
        """
        Hide payload inside carrier, write result to output.

        Args:
            carrier: Path to the base/cover file.
            payload: Path to the file being hidden.
            output:  Path to write the stego output.

        Returns:
            True on success.
        """
        try:
            return self._encode_impl(carrier, payload, output, **kwargs)
        except Exception as e:
            logger.error("[%s] encode() failed: %s", self.MODULE_NAME, e)
            return False

    def decode(self, carrier: str, stego: str, output: str, **kwargs) -> bool:
        """
        Extract hidden payload from stego file, write recovered data to output.

        Args:
            carrier: Path to the original unmodified base file.
            stego:   Path to the stego file that contains hidden data.
            output:  Path to write the recovered payload.

        Returns:
            True on success.
        """
        try:
            return self._decode_impl(carrier, stego, output, **kwargs)
        except Exception as e:
            logger.error("[%s] decode() failed: %s", self.MODULE_NAME, e)
            return False

    # --- Map generic interface to encode/decode ---

    def send(self, data: Any, **kwargs) -> bool:
        """Alias: send(carrier, payload, output) → encode()."""
        if not isinstance(data, (list, tuple)) or len(data) < 3:
            raise ValueError(
                "StegaModule.send() expects (carrier, payload, output). "
                "Use encode() directly for clarity."
            )
        return self.encode(data[0], data[1], data[2], **kwargs)

    def receive(self, **kwargs) -> Any:
        """Alias: receive(carrier, stego, output) — pass paths as kwargs."""
        carrier = kwargs.pop("carrier")
        stego   = kwargs.pop("stego")
        output  = kwargs.pop("output")
        return self.decode(carrier, stego, output, **kwargs)

    # --- Abstract hooks ---

    @abc.abstractmethod
    def _encode_impl(self, carrier: str, payload: str, output: str, **kwargs) -> bool:
        """Implement steganographic encoding."""

    @abc.abstractmethod
    def _decode_impl(self, carrier: str, stego: str, output: str, **kwargs) -> bool:
        """Implement steganographic decoding."""

    # --- Stega modules don't use _send_impl / _listen_impl ---

    def _send_impl(self, data: Any, **kwargs) -> bool:
        return self.send(data, **kwargs)

    def _listen_impl(self, callback: Callable, **kwargs) -> None:
        raise NotImplementedError(
            "StegaModule does not support listen(). Use decode() instead."
        )
