

from __future__ import annotations

import struct

_MASK = 0xFFFFFFFFFFFFFFFF
_SC_CONST = 0xDEADBEEFDEADBEEF
_SC_NUMVARS = 12
_SC_BLOCKSIZE = _SC_NUMVARS * 8
_SC_BUFSIZE = 2 * _SC_BLOCKSIZE


def _rot(x: int, k: int) -> int:
    return ((x << k) | (x >> (64 - k))) & _MASK


def _short_mix(h0: int, h1: int, h2: int, h3: int) -> tuple[int, int, int, int]:
    for r0, r1, r2, r3 in ((50, 52, 30, 41), (54, 48, 38, 37), (62, 34, 5, 36)):
        h2 = _rot(h2, r0); h2 = (h2 + h3) & _MASK; h0 ^= h2
        h3 = _rot(h3, r1); h3 = (h3 + h0) & _MASK; h1 ^= h3
        h0 = _rot(h0, r2); h0 = (h0 + h1) & _MASK; h2 ^= h0
        h1 = _rot(h1, r3); h1 = (h1 + h2) & _MASK; h3 ^= h1
    return h0, h1, h2, h3


def _short_end(h0: int, h1: int, h2: int, h3: int) -> tuple[int, int, int, int]:
    h3 ^= h2; h2 = _rot(h2, 15); h3 = (h3 + h2) & _MASK
    h0 ^= h3; h3 = _rot(h3, 52); h0 = (h0 + h3) & _MASK
    h1 ^= h0; h0 = _rot(h0, 26); h1 = (h1 + h0) & _MASK
    h2 ^= h1; h1 = _rot(h1, 51); h2 = (h2 + h1) & _MASK
    h3 ^= h2; h2 = _rot(h2, 28); h3 = (h3 + h2) & _MASK
    h0 ^= h3; h3 = _rot(h3, 9); h0 = (h0 + h3) & _MASK
    h1 ^= h0; h0 = _rot(h0, 47); h1 = (h1 + h0) & _MASK
    h2 ^= h1; h1 = _rot(h1, 54); h2 = (h2 + h1) & _MASK
    h3 ^= h2; h2 = _rot(h2, 32); h3 = (h3 + h2) & _MASK
    h0 ^= h3; h3 = _rot(h3, 25); h0 = (h0 + h3) & _MASK
    h1 ^= h0; h0 = _rot(h0, 63); h1 = (h1 + h0) & _MASK
    return h0, h1, h2, h3


def _short(message: bytes, seed1: int, seed2: int) -> tuple[int, int]:
    length = len(message)
    a, b, c, d = seed1, seed2, _SC_CONST, _SC_CONST
    pos = 0
    remainder = length % 32
    if length > 15:
        end = (length // 32) * 32
        while pos < end:
            w0, w1, w2, w3 = struct.unpack_from("<4Q", message, pos)
            c = (c + w0) & _MASK
            d = (d + w1) & _MASK
            a, b, c, d = _short_mix(a, b, c, d)
            a = (a + w2) & _MASK
            b = (b + w3) & _MASK
            pos += 32
        if remainder >= 16:
            w0, w1 = struct.unpack_from("<2Q", message, pos)
            c = (c + w0) & _MASK
            d = (d + w1) & _MASK
            a, b, c, d = _short_mix(a, b, c, d)
            pos += 16
            remainder -= 16
    d = (d + ((length << 56) & _MASK)) & _MASK
    tail = message[pos : pos + remainder]
    if remainder >= 12:
        c = (c + struct.unpack_from("<Q", tail, 0)[0]) & _MASK
        extra = int.from_bytes(tail[8:], "little")
        d = (d + extra) & _MASK
    elif remainder >= 8:
        c = (c + struct.unpack_from("<Q", tail, 0)[0]) & _MASK
        if remainder > 8:
            d = (d + int.from_bytes(tail[8:], "little")) & _MASK
    elif remainder > 0:
        c = (c + int.from_bytes(tail, "little")) & _MASK
    else:
        c = (c + _SC_CONST) & _MASK
        d = (d + _SC_CONST) & _MASK
    a, b, c, d = _short_end(a, b, c, d)
    return a, b


def _mix(data: tuple[int, ...], s: list[int]) -> None:
    rots = (11, 32, 43, 31, 17, 28, 39, 57, 55, 54, 22, 46)
    for i in range(12):
        s[i] = (s[i] + data[i]) & _MASK
        s[(i + 2) % 12] ^= s[(i + 10) % 12]
        s[(i + 11) % 12] ^= s[i]
        s[i] = _rot(s[i], rots[i])
        s[(i + 11) % 12] = (s[(i + 11) % 12] + s[(i + 1) % 12]) & _MASK


def _end_partial(h: list[int]) -> None:
    rots = (44, 15, 34, 21, 38, 33, 10, 13, 38, 53, 42, 54)
    for i in range(12):
        j = (i + 11) % 12
        h[j] = (h[j] + h[(j + 2) % 12]) & _MASK
        h[(j + 3) % 12] ^= h[j]
        h[(j + 2) % 12] = _rot(h[(j + 2) % 12], rots[i])


def hash128(message: bytes, seed1: int = 0, seed2: int = 0) -> tuple[int, int]:


    message = bytes(message)
    length = len(message)
    if length < _SC_BUFSIZE:
        return _short(message, seed1 & _MASK, seed2 & _MASK)
    h = [seed1 & _MASK, seed2 & _MASK, _SC_CONST] * 4
    blocks = length // _SC_BLOCKSIZE
    for index in range(blocks):
        _mix(struct.unpack_from("<12Q", message, index * _SC_BLOCKSIZE), h)
    remainder = length - blocks * _SC_BLOCKSIZE
    buf = bytearray(_SC_BLOCKSIZE)
    buf[:remainder] = message[blocks * _SC_BLOCKSIZE :]
    buf[_SC_BLOCKSIZE - 1] = remainder
    data = struct.unpack("<12Q", bytes(buf))
    for i in range(12):
        h[i] = (h[i] + data[i]) & _MASK
    _end_partial(h)
    _end_partial(h)
    _end_partial(h)
    return h[0], h[1]


def hash128_bytes(message: bytes, seed1: int = 0, seed2: int = 0) -> bytes:


    h1, h2 = hash128(message, seed1, seed2)
    return struct.pack("<QQ", h1, h2)


def cluster_id_from_label(label: str) -> int:


    return hash128(label.encode("utf-16-le"))[0]
