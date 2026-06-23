import pytest

from pyexfil.includes.exceptions import (
    FileDoesNotExist, InvalidPacketFormat, DecryptionFailed,
    CompressionError, PacketMissing, HashMismatch,
    UnsupportedPythonVersion, LibraryNotFound, PermissionDenied,
    UnsupportedOS, FetchDataError, SendDataError,
)


@pytest.mark.parametrize("exc_class,args", [
    (FileDoesNotExist,        ("/tmp/missing.txt",)),
    (InvalidPacketFormat,     ("bad_packet",)),
    (DecryptionFailed,        ("bad key",)),
    (CompressionError,        ("corrupted data",)),
    (PacketMissing,           (3,)),
    (HashMismatch,            ("abc123", "def456")),
    (UnsupportedPythonVersion,("2.7",)),
    (LibraryNotFound,         ("librosa",)),
    (PermissionDenied,        ("read",)),
    (UnsupportedOS,           ("Windows 95",)),
    (FetchDataError,          ("http://example.com",)),
    (SendDataError,           ("http://example.com",)),
])
def test_exception_raises(exc_class, args):
    with pytest.raises(exc_class):
        raise exc_class(*args)


@pytest.mark.parametrize("exc_class,args", [
    (FileDoesNotExist,        ("/tmp/missing.txt",)),
    (InvalidPacketFormat,     ("bad_packet",)),
    (DecryptionFailed,        ("bad key",)),
    (CompressionError,        ("corrupted",)),
    (PacketMissing,           (5,)),
    (HashMismatch,            ("aaa", "bbb")),
    (UnsupportedPythonVersion,("2.6",)),
    (LibraryNotFound,         ("numpy",)),
    (PermissionDenied,        ("write",)),
    (UnsupportedOS,           ("DOS",)),
    (FetchDataError,          ("http://x.com",)),
    (SendDataError,           ("http://x.com",)),
])
def test_exception_message(exc_class, args):
    try:
        raise exc_class(*args)
    except exc_class as e:
        assert str(e)
        assert hasattr(e, 'message')
