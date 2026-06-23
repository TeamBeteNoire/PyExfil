"""
Tests for the PyExfil base class hierarchy.
Verifies contracts, inheritance, and interface behaviour without
requiring network sockets or hardware devices.
"""

import threading
import pytest

from pyexfil.includes.base import (
    PyExfilModule, NetworkModule, CommModule, PhysicalModule, StegaModule,
)


# ---------------------------------------------------------------------------
# Minimal concrete implementations used only in tests
# ---------------------------------------------------------------------------

class _MinimalNetwork(NetworkModule):
    MODULE_NAME = "TestNetwork"
    PROTOCOL    = "test/tcp"

    def _send_impl(self, data, **kwargs) -> bool:
        self._last_sent = data
        return True

    def _listen_impl(self, callback, **kwargs) -> None:
        callback(b"hello", {"sender_addr": ("127.0.0.1", 9999)})


class _MinimalComm(CommModule):
    MODULE_NAME = "TestComm"
    PROTOCOL    = "test/udp"

    def _send_impl(self, data, **kwargs) -> bool:
        self._last_sent = data
        return True

    def _broadcast_impl(self, data, **kwargs) -> bool:
        self._last_broadcast = data
        return True

    def _listen_impl(self, callback, **kwargs) -> None:
        callback(b"c2msg", {"sender_addr": ("10.0.0.1", 1234)})


class _MinimalPhysical(PhysicalModule):
    MODULE_NAME = "TestPhysical"
    PROTOCOL    = "test/audio"

    def _send_impl(self, data, **kwargs) -> bool:
        self._last_sent = data
        return True


class _MinimalStega(StegaModule):
    MODULE_NAME = "TestStega"
    PROTOCOL    = "test/stega"

    def _encode_impl(self, carrier, payload, output, **kwargs) -> bool:
        self._encoded = (carrier, payload, output)
        return True

    def _decode_impl(self, carrier, stego, output, **kwargs) -> bool:
        self._decoded = (carrier, stego, output)
        return True


# ---------------------------------------------------------------------------
# PyExfilModule — abstract contract
# ---------------------------------------------------------------------------

class TestPyExfilModuleAbstract:

    def test_cannot_instantiate_abstract_base(self):
        with pytest.raises(TypeError):
            PyExfilModule()

    def test_network_subclass_without_impl_raises_on_use(self):
        # NetworkModule provides non-abstract raise-stubs so subclasses can
        # implement only the direction they need (send-only or listen-only).
        # The error surfaces at call time, not instantiation time.
        class Incomplete(NetworkModule):
            pass
        m = Incomplete(host="x", port=1)
        with pytest.raises(NotImplementedError):
            m._send_impl(b"x")

    def test_cannot_instantiate_stega_without_impl(self):
        class Incomplete(StegaModule):
            def _encode_impl(self, *a, **kw): return True
            # _decode_impl missing
        with pytest.raises(TypeError):
            Incomplete()


# ---------------------------------------------------------------------------
# NetworkModule
# ---------------------------------------------------------------------------

class TestNetworkModule:

    def setup_method(self):
        self.mod = _MinimalNetwork(host="127.0.0.1", port=9999)

    def test_send_returns_true(self):
        assert self.mod.send(b"data") is True

    def test_send_stores_data(self):
        self.mod.send(b"payload")
        assert self.mod._last_sent == b"payload"

    def test_send_exception_returns_false(self):
        class Broken(_MinimalNetwork):
            def _send_impl(self, data, **kw):
                raise RuntimeError("boom")
        b = Broken(host="x", port=1)
        assert b.send(b"x") is False

    def test_listen_blocking_calls_callback(self):
        results = []
        self.mod.listen(callback=lambda d, m: results.append(d), blocking=True)
        assert results == [b"hello"]

    def test_listen_nonblocking_returns_thread(self):
        done = threading.Event()
        def cb(data, meta):
            done.set()
        t = self.mod.listen(callback=cb, blocking=False)
        assert isinstance(t, threading.Thread)
        done.wait(timeout=2)
        assert done.is_set()

    def test_broadcast_defaults_to_send(self):
        assert self.mod.broadcast(b"bcast") is True
        assert self.mod._last_sent == b"bcast"

    def test_receive_raises_not_implemented(self):
        with pytest.raises(NotImplementedError):
            self.mod.receive()

    def test_repr_contains_protocol(self):
        r = repr(self.mod)
        assert "test/tcp" in r

    def test_stop_sets_event(self):
        self.mod.stop()
        assert self.mod._stop_event.is_set()

    def test_module_type(self):
        assert self.mod.MODULE_TYPE == "network"

    def test_constructor_attrs(self):
        m = _MinimalNetwork(host="1.2.3.4", port=1234, packet_delay=0.1, max_packet_size=256)
        assert m.host == "1.2.3.4"
        assert m.port == 1234
        assert m.packet_delay == 0.1
        assert m.max_packet_size == 256


# ---------------------------------------------------------------------------
# CommModule
# ---------------------------------------------------------------------------

class TestCommModule:

    def setup_method(self):
        self.mod = _MinimalComm(enc_key="secret")

    def test_send_returns_true(self):
        assert self.mod.send(b"msg") is True

    def test_broadcast_returns_true(self):
        assert self.mod.broadcast(b"bcast") is True

    def test_broadcast_stores_separately_from_send(self):
        self.mod.send(b"s")
        self.mod.broadcast(b"b")
        assert self.mod._last_sent == b"s"
        assert self.mod._last_broadcast == b"b"

    def test_listen_delivers_to_callback(self):
        received = []
        self.mod.listen(callback=lambda d, m: received.append(d), blocking=True)
        assert received == [b"c2msg"]

    def test_on_message_stored(self):
        cb = lambda d, m: None
        m = _MinimalComm(on_message=cb)
        assert m.on_message is cb

    def test_module_type(self):
        assert self.mod.MODULE_TYPE == "comm"


# ---------------------------------------------------------------------------
# PhysicalModule
# ---------------------------------------------------------------------------

class TestPhysicalModule:

    def setup_method(self):
        self.mod = _MinimalPhysical()

    def test_send_returns_true(self):
        assert self.mod.send(b"data") is True

    def test_listen_raises_not_implemented(self):
        with pytest.raises(NotImplementedError):
            self.mod.listen(blocking=True)

    def test_receive_raises_not_implemented(self):
        with pytest.raises(NotImplementedError):
            self.mod.receive()

    def test_module_type(self):
        assert self.mod.MODULE_TYPE == "physical"

    def test_no_enc_key(self):
        assert self.mod.enc_key == ""


# ---------------------------------------------------------------------------
# StegaModule
# ---------------------------------------------------------------------------

class TestStegaModule:

    def setup_method(self):
        self.mod = _MinimalStega()

    def test_encode_returns_true(self):
        assert self.mod.encode("carrier.png", "secret.txt", "out.png") is True

    def test_encode_passes_correct_args(self):
        self.mod.encode("c.png", "p.txt", "o.png")
        assert self.mod._encoded == ("c.png", "p.txt", "o.png")

    def test_decode_returns_true(self):
        assert self.mod.decode("carrier.png", "stego.png", "out.txt") is True

    def test_decode_passes_correct_args(self):
        self.mod.decode("c.png", "s.png", "o.txt")
        assert self.mod._decoded == ("c.png", "s.png", "o.txt")

    def test_send_alias_calls_encode(self):
        self.mod.send(["a.png", "b.txt", "c.png"])
        assert self.mod._encoded == ("a.png", "b.txt", "c.png")

    def test_send_alias_wrong_args_raises_value_error(self):
        with pytest.raises(ValueError):
            self.mod.send("just_a_string")

    def test_receive_alias_calls_decode(self):
        self.mod.receive(carrier="c.png", stego="s.png", output="o.txt")
        assert self.mod._decoded == ("c.png", "s.png", "o.txt")

    def test_encode_exception_returns_false(self):
        class Broken(_MinimalStega):
            def _encode_impl(self, *a, **kw):
                raise IOError("disk full")
        b = Broken()
        assert b.encode("a", "b", "c") is False

    def test_listen_raises_not_implemented(self):
        with pytest.raises(NotImplementedError):
            self.mod.listen(blocking=True)

    def test_module_type(self):
        assert self.mod.MODULE_TYPE == "stega"

    def test_no_enc_key(self):
        assert self.mod.enc_key == ""


# ---------------------------------------------------------------------------
# Inheritance chain
# ---------------------------------------------------------------------------

class TestInheritanceChain:

    def test_network_is_pyexfil_module(self):
        m = _MinimalNetwork(host="x", port=1)
        assert isinstance(m, PyExfilModule)
        assert isinstance(m, NetworkModule)

    def test_comm_is_pyexfil_module(self):
        m = _MinimalComm()
        assert isinstance(m, PyExfilModule)
        assert isinstance(m, CommModule)

    def test_physical_is_pyexfil_module(self):
        m = _MinimalPhysical()
        assert isinstance(m, PyExfilModule)
        assert isinstance(m, PhysicalModule)

    def test_stega_is_pyexfil_module(self):
        m = _MinimalStega()
        assert isinstance(m, PyExfilModule)
        assert isinstance(m, StegaModule)

    def test_cross_type_not_confused(self):
        n = _MinimalNetwork(host="x", port=1)
        assert not isinstance(n, CommModule)
        assert not isinstance(n, StegaModule)
