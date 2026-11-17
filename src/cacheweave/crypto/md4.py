

from __future__ import annotations

import struct

_MASK = 0xFFFFFFFF


def _rotl(x: int, n: int) -> int:
    return ((x << n) | (x >> (32 - n))) & _MASK


def md4(data: bytes) -> bytes:
    message = bytearray(data)
    bit_length = (len(message) * 8) & 0xFFFFFFFFFFFFFFFF
    message.append(0x80)
    while len(message) % 64 != 56:
        message.append(0)
    message += struct.pack("<Q", bit_length)
    a, b, c, d = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476
    for offset in range(0, len(message), 64):
        x = struct.unpack_from("<16I", message, offset)
        aa, bb, cc, dd = a, b, c, d

        def f(x_, y, z):
            return (x_ & y) | (~x_ & z)

        def g(x_, y, z):
            return (x_ & y) | (x_ & z) | (y & z)

        def h(x_, y, z):
            return x_ ^ y ^ z

        for i in (0, 4, 8, 12):
            a = _rotl((a + f(b, c, d) + x[i]) & _MASK, 3)
            d = _rotl((d + f(a, b, c) + x[i + 1]) & _MASK, 7)
            c = _rotl((c + f(d, a, b) + x[i + 2]) & _MASK, 11)
            b = _rotl((b + f(c, d, a) + x[i + 3]) & _MASK, 19)
        for i in (0, 1, 2, 3):
            a = _rotl((a + g(b, c, d) + x[i] + 0x5A827999) & _MASK, 3)
            d = _rotl((d + g(a, b, c) + x[i + 4] + 0x5A827999) & _MASK, 5)
            c = _rotl((c + g(d, a, b) + x[i + 8] + 0x5A827999) & _MASK, 9)
            b = _rotl((b + g(c, d, a) + x[i + 12] + 0x5A827999) & _MASK, 13)
        for i in (0, 2, 1, 3):
            a = _rotl((a + h(b, c, d) + x[i] + 0x6ED9EBA1) & _MASK, 3)
            d = _rotl((d + h(a, b, c) + x[i + 8] + 0x6ED9EBA1) & _MASK, 9)
            c = _rotl((c + h(d, a, b) + x[i + 4] + 0x6ED9EBA1) & _MASK, 11)
            b = _rotl((b + h(c, d, a) + x[i + 12] + 0x6ED9EBA1) & _MASK, 15)
        a = (a + aa) & _MASK
        b = (b + bb) & _MASK
        c = (c + cc) & _MASK
        d = (d + dd) & _MASK
    return struct.pack("<4I", a, b, c, d)
