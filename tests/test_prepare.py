import os
import tempfile
import pytest

from pyexfil.includes.prepare import PrepFile, PrepString, DecodePacket, RebuildFile, _splitString


class TestSplitString:

    def test_basic_bytes(self):
        data = b"abcdefgh"
        result = _splitString(data, 3)
        assert result == [b"abc", b"def", b"gh"]

    def test_basic_str(self):
        result = _splitString("hello", 2)
        assert result == ["he", "ll", "o"]

    def test_invalid_length_type(self):
        assert _splitString(b"data", "3") is False

    def test_invalid_data_type(self):
        assert _splitString(12345, 2) is False


class TestPrepFile:

    def _make_temp_file(self, content=b"test content for exfil"):
        f = tempfile.NamedTemporaryFile(delete=False)
        f.write(content)
        f.close()
        return f.name

    def test_returns_dict(self):
        path = self._make_temp_file()
        try:
            result = PrepFile(path, kind='binary', enc_key="")
            assert isinstance(result, dict)
        finally:
            os.unlink(path)

    def test_has_required_keys(self):
        path = self._make_temp_file()
        try:
            result = PrepFile(path, kind='binary', enc_key="")
            for key in ('FileName', 'Packets', 'PacketsCount', 'RawHash', 'FileSequenceID'):
                assert key in result, "Missing key: %s" % key
        finally:
            os.unlink(path)

    def test_packet_count_matches(self):
        path = self._make_temp_file()
        try:
            result = PrepFile(path, kind='binary', enc_key="")
            assert len(result['Packets']) == result['PacketsCount']
        finally:
            os.unlink(path)

    def test_invalid_kind(self):
        path = self._make_temp_file()
        try:
            result = PrepFile(path, kind='xml')
            assert result is False
        finally:
            os.unlink(path)

    def test_missing_file(self):
        result = PrepFile('/nonexistent/path/file.txt')
        assert result is False

    def test_ascii_kind(self):
        path = self._make_temp_file()
        try:
            result = PrepFile(path, kind='ascii', enc_key="")
            assert result is not False
            assert result['PacketsCount'] >= 1
        finally:
            os.unlink(path)

    def test_encryption_flag_with_key(self):
        path = self._make_temp_file()
        try:
            result = PrepFile(path, enc_key="mykey")
            assert result['EncryptionFlag'] is True
        finally:
            os.unlink(path)

    def test_encryption_flag_without_key(self):
        path = self._make_temp_file()
        try:
            result = PrepFile(path, enc_key="")
            assert result['EncryptionFlag'] is False
        finally:
            os.unlink(path)


class TestPrepString:

    def test_basic(self):
        result = PrepString(b"hello world", enc_key=b"")
        assert isinstance(result, dict)
        assert 'Packets' in result

    def test_str_input(self):
        result = PrepString("hello world", enc_key="")
        assert isinstance(result, dict)

    def test_with_encryption(self):
        result = PrepString(b"secret data", enc_key=b"mykey")
        assert result['EncryptionFlag'] is True


class TestGeneral:

    def test_does_file_exist_false(self):
        from pyexfil.includes.general import does_file_exist
        assert does_file_exist('/nonexistent/path') is False

    def test_does_file_exist_true(self):
        from pyexfil.includes.general import does_file_exist
        f = tempfile.NamedTemporaryFile(delete=False)
        f.close()
        try:
            assert does_file_exist(f.name) is True
        finally:
            os.unlink(f.name)

    def test_inet_aton_valid(self):
        from pyexfil.includes.general import inet_aton
        packed = b'\x7f\x00\x00\x01'
        result = inet_aton(packed)
        assert result == '127.0.0.1'

    def test_inet_aton_invalid(self):
        from pyexfil.includes.general import inet_aton
        assert inet_aton(b'\x00') is False

    def test_icmp_checksum_bytes(self):
        from pyexfil.includes.general import _icmp_checksum
        result = _icmp_checksum(b'\x08\x00\x00\x00\x00\x01\x00\x01')
        assert isinstance(result, int)

    def test_split_every_n(self):
        from pyexfil.includes.general import _split_every_n
        result = _split_every_n("abcdef", 2)
        assert result == ["ab", "cd", "ef"]
