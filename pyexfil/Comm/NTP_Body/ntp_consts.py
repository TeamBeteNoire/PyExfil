import base64

SERVER      = "127.0.0.1"
NTP_PORT    = 123
KEY         = base64.b64decode(b'VEhBVElTQURFQURQQVJST1Qh')
RECV_BUFFER = 1024


def _buildNTP() -> bytes:
    """Build a minimal NTP Symmetric-Active mode header."""
    pyld  = b"\xd9"            # v3, Symmetric-Active mode
    pyld += b"\x00"            # stratum: unspecified
    pyld += b"\x0a"            # poll interval: 1024 s
    pyld += b"\xfa"            # clock precision
    pyld += b"\x00" * 4       # root delay
    pyld += b"\x00\x01\x02\x90"  # root dispersion
    pyld += b"\x00" * 4       # reference ID
    return pyld
