from __future__ import annotations
from typing import Any

def summarize_quic(datagram_len: int, first_byte: int | None=None, version: int | None=None) -> dict[str, Any]:
    if datagram_len<=0: return {}
    first_byte = 0 if first_byte is None else int(first_byte)
    long_header=bool(first_byte & 0x80)
    fixed_bit=bool(first_byte & 0x40)
    return {
        'transport':'QUIC',
        'header_form':'long' if long_header else 'short',
        'fixed_bit':fixed_bit,
        'version':version,
        'packet_length':datagram_len,
    }
