

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import struct
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from ..formats.terse_codec import (
    TerseDecodeError,
    TerseReader,
    build_envelope,
    decode_envelope,
    encode_uleb128,
)
from .syzygy_crypt_session import (
    CURRENT_BLOCK_BYTES,
    content_block_key,
    decrypt_aligned,
    derive_key_manager_iv,
    encrypt_aligned,
    hmac_key_block_key,
    hmac_value_block_key,
)


MAX_ENCRYPTED_SHARD_SIZE = 0xFF80
FOOTER_SIZE = 0x80
MAX_PHYSICAL_SHARD_SIZE = MAX_ENCRYPTED_SHARD_SIZE + FOOTER_SIZE
FOOTER_FORMAT_VERSION = 1
HMAC_KEY_SIZE = 0x10
HMAC_VALUE_SIZE = 0x40


def _read_terse_array(reader: TerseReader, size: int, label: str) -> bytes:


    count = reader.read_uleb128(32)
    if count != size:
        raise ProtectedStreamDecodeError(
            f"{label} array has count {count}, expected {size}"
        )
    return reader.read_exact(size)


class ProtectedStreamDecodeError(ValueError):
    pass


class ProtectedStreamAuthenticationError(ProtectedStreamDecodeError):
    pass


@dataclass(frozen=True)
class ProtectedStreamFooter:
    format_version: int
    session_id: int
    salt: int
    encrypted_hmac_key: bytes
    hmac_value: bytes
    terse_payload_size: int
    zero_padding_size: int

    def to_json_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["encrypted_hmac_key"] = self.encrypted_hmac_key.hex()
        result["hmac_value"] = self.hmac_value.hex()
        return result


@dataclass(frozen=True)
class ProtectedStreamShard:
    index: int
    physical_offset: int
    encrypted_size: int
    footer_offset: int
    logical_offset: int
    logical_size: int
    inner_padding_size: int
    ciphertext_sha256: str
    footer: ProtectedStreamFooter

    def to_json_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["footer"] = self.footer.to_json_dict()
        return result


@dataclass(frozen=True)
class ProtectedStreamLayout:
    physical_size: int
    logical_size: int
    crypto_block_size: int
    inner_padding_size: int
    outer_padding_size: int
    outer_padding_sha256: str
    shards: tuple[ProtectedStreamShard, ...]

    def to_json_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["shards"] = [shard.to_json_dict() for shard in self.shards]
        return result


def _validate_block_size(block_size: int) -> None:
    if not 0 < block_size <= MAX_ENCRYPTED_SHARD_SIZE:
        raise ValueError(
            f"crypto block size must be 1..0x{MAX_ENCRYPTED_SHARD_SIZE:x}"
        )


def protected_padding_size(logical_size: int, block_size: int) -> int:


    if logical_size < 0:
        raise ValueError("logical size cannot be negative")
    _validate_block_size(block_size)
    remainder = logical_size % block_size
    return 0 if remainder == 0 else block_size - remainder


def physical_size_for_logical_size(logical_size: int, block_size: int) -> int:


    padding = protected_padding_size(logical_size, block_size)
    aligned_size = logical_size + padding
    shard_count = (
        (aligned_size + MAX_ENCRYPTED_SHARD_SIZE - 1)
        // MAX_ENCRYPTED_SHARD_SIZE
        if aligned_size
        else 0
    )
    physical_size = aligned_size + shard_count * FOOTER_SIZE + padding
    if physical_size % block_size != padding:
        raise ValueError(
            "block size is incompatible with the native protected-stream "
            "size invariant"
        )
    return physical_size


def logical_size_from_physical_size(physical_size: int, block_size: int) -> int:


    if physical_size < 0:
        raise ValueError("physical size cannot be negative")
    _validate_block_size(block_size)
    padding = physical_size % block_size
    core_size = physical_size - 2 * padding
    if core_size < 0:
        raise ProtectedStreamDecodeError(
            "physical stream is smaller than its duplicated padding"
        )
    full_shards, partial_size = divmod(core_size, MAX_PHYSICAL_SHARD_SIZE)
    if partial_size == 0:
        logical_size = full_shards * MAX_ENCRYPTED_SHARD_SIZE
    else:
        if not FOOTER_SIZE < partial_size <= MAX_PHYSICAL_SHARD_SIZE:
            raise ProtectedStreamDecodeError(
                f"invalid final physical shard size 0x{partial_size:x}"
            )
        logical_size = (
            full_shards * MAX_ENCRYPTED_SHARD_SIZE
            + partial_size
            - FOOTER_SIZE
        )
    try:
        expected = physical_size_for_logical_size(logical_size, block_size)
    except ValueError as error:
        raise ProtectedStreamDecodeError(str(error)) from error
    if expected != physical_size:
        raise ProtectedStreamDecodeError(
            f"physical size 0x{physical_size:x} is not canonical; "
            f"logical size 0x{logical_size:x} would encode as 0x{expected:x}"
        )
    return logical_size


def decode_protected_footer(data: bytes) -> ProtectedStreamFooter:


    if len(data) != FOOTER_SIZE:
        raise ProtectedStreamDecodeError(
            f"footer is 0x{len(data):x} bytes, expected 0x{FOOTER_SIZE:x}"
        )
    try:
        envelope = decode_envelope(data, allow_trailing=True)
    except TerseDecodeError as error:
        raise ProtectedStreamDecodeError(f"invalid footer Terse stream: {error}") from error
    payload_end = 9 + envelope.payload_size
    trailing = data[payload_end:]
    if any(trailing):
        raise ProtectedStreamDecodeError("footer has nonzero bytes after its Terse stream")
    reader = TerseReader(envelope.payload)
    try:
        format_version = reader.read_exact(1)[0]
        session_id = reader.read_uleb128(32)
        salt = reader.read_uleb128(32)
        encrypted_hmac_key = _read_terse_array(reader, HMAC_KEY_SIZE, "encrypted HMAC key")
        hmac_value = _read_terse_array(reader, HMAC_VALUE_SIZE, "encrypted HMAC value")
    except TerseDecodeError as error:
        raise ProtectedStreamDecodeError(f"truncated footer payload: {error}") from error
    if format_version != FOOTER_FORMAT_VERSION:
        raise ProtectedStreamDecodeError(
            f"unsupported footer version {format_version}, "
            f"expected {FOOTER_FORMAT_VERSION}"
        )
    if not reader.finished:
        raise ProtectedStreamDecodeError(
            f"footer payload has {reader.remaining} trailing bytes"
        )
    return ProtectedStreamFooter(
        format_version=format_version,
        session_id=session_id,
        salt=salt,
        encrypted_hmac_key=encrypted_hmac_key,
        hmac_value=hmac_value,
        terse_payload_size=envelope.payload_size,
        zero_padding_size=len(trailing),
    )


def build_protected_footer(
    session_id: int,
    salt: int,
    encrypted_hmac_key: bytes,
    hmac_value: bytes,
) -> bytes:


    if len(encrypted_hmac_key) != HMAC_KEY_SIZE:
        raise ValueError("encrypted HMAC key must be exactly 16 bytes")
    if len(hmac_value) != HMAC_VALUE_SIZE:
        raise ValueError("HMAC value must be exactly 64 bytes")
    payload = (
        bytes((FOOTER_FORMAT_VERSION,))
        + encode_uleb128(session_id, 32)
        + encode_uleb128(salt, 32)
        + encode_uleb128(HMAC_KEY_SIZE, 32)
        + encrypted_hmac_key
        + encode_uleb128(HMAC_VALUE_SIZE, 32)
        + hmac_value
    )
    stream = build_envelope(payload)
    if len(stream) > FOOTER_SIZE:
        raise ValueError("encoded footer exceeds its fixed 0x80-byte slot")
    return stream.ljust(FOOTER_SIZE, b"\0")


def inspect_protected_stream(data: bytes, block_size: int) -> ProtectedStreamLayout:


    logical_size = logical_size_from_physical_size(len(data), block_size)
    padding = protected_padding_size(logical_size, block_size)
    outer_padding = data[len(data) - padding :] if padding else b""
    framed_size = len(data) - padding
    aligned_plaintext_size = logical_size + padding
    shard_count = (
        (aligned_plaintext_size + MAX_ENCRYPTED_SHARD_SIZE - 1)
        // MAX_ENCRYPTED_SHARD_SIZE
        if aligned_plaintext_size
        else 0
    )
    shards: list[ProtectedStreamShard] = []
    cursor = 0
    logical_offset = 0
    remaining_aligned = aligned_plaintext_size
    for index in range(shard_count):
        encrypted_size = min(MAX_ENCRYPTED_SHARD_SIZE, remaining_aligned)
        footer_offset = cursor + encrypted_size
        footer_end = footer_offset + FOOTER_SIZE
        if footer_end > framed_size:
            raise ProtectedStreamDecodeError(
                f"shard {index} footer ends past protected framing"
            )
        footer = decode_protected_footer(data[footer_offset:footer_end])
        inner_padding = padding if index + 1 == shard_count else 0
        shard_logical_size = encrypted_size - inner_padding
        if shard_logical_size < 0:
            raise ProtectedStreamDecodeError(
                f"shard {index} is smaller than final inner padding"
            )
        ciphertext = data[cursor:footer_offset]
        shards.append(
            ProtectedStreamShard(
                index=index,
                physical_offset=cursor,
                encrypted_size=encrypted_size,
                footer_offset=footer_offset,
                logical_offset=logical_offset,
                logical_size=shard_logical_size,
                inner_padding_size=inner_padding,
                ciphertext_sha256=hashlib.sha256(ciphertext).hexdigest(),
                footer=footer,
            )
        )
        cursor = footer_end
        logical_offset += shard_logical_size
        remaining_aligned -= encrypted_size
    if cursor != framed_size or remaining_aligned != 0 or logical_offset != logical_size:
        raise ProtectedStreamDecodeError(
            "protected-stream shard inventory does not consume the canonical sizes"
        )
    return ProtectedStreamLayout(
        physical_size=len(data),
        logical_size=logical_size,
        crypto_block_size=block_size,
        inner_padding_size=padding,
        outer_padding_size=padding,
        outer_padding_sha256=hashlib.sha256(outer_padding).hexdigest(),
        shards=tuple(shards),
    )


def authenticate_and_decrypt_protected_stream(
    data: bytes,
    stream_key: bytes,
    stream_salt: bytes,
    *,
    block_size: int = CURRENT_BLOCK_BYTES,
    expected_session_id: int | None = None,
) -> bytes:


    layout = inspect_protected_stream(data, block_size)
    if not layout.shards:
        return b""

    if expected_session_id is None:
        expected_session_id = layout.shards[0].footer.session_id
    if expected_session_id < 0 or expected_session_id > 0xFFFFFFFF:
        raise ValueError("expected_session_id must fit uint32")

    authenticated: list[tuple[ProtectedStreamShard, bytes]] = []
    for shard in layout.shards:
        footer = shard.footer
        if footer.session_id != expected_session_id:
            raise ProtectedStreamAuthenticationError(
                f"shard {shard.index} session ID 0x{footer.session_id:08x} "
                f"does not match 0x{expected_session_id:08x}"
            )
        ciphertext = data[
            shard.physical_offset : shard.physical_offset + shard.encrypted_size
        ]
        if not verify_shard_hmac(
            shard, ciphertext, stream_key, stream_salt, block_size=block_size
        ):
            raise ProtectedStreamAuthenticationError(
                f"shard {shard.index} HMAC-SHA512 verification failed"
            )
        authenticated.append((shard, ciphertext))

    plaintext = bytearray()
    for shard, ciphertext in authenticated:
        plaintext.extend(
            decrypt_shard_unauthenticated(
                shard, ciphertext, stream_key, stream_salt, block_size=block_size
            )
        )
    if len(plaintext) != layout.logical_size:
        raise ProtectedStreamDecodeError(
            "decrypted stream length does not match the canonical logical size"
        )
    return bytes(plaintext)


def compute_shard_hmac(
    shard_index: int,
    footer_salt: int,
    ciphertext: bytes,
    hmac_key: bytes,
) -> bytes:


    return hmac.new(
        hmac_key,
        struct.pack("<II", footer_salt, shard_index) + ciphertext,
        hashlib.sha512,
    ).digest()


def verify_shard_hmac(
    shard: ProtectedStreamShard,
    ciphertext: bytes,
    stream_key: bytes,
    stream_salt: bytes,
    *,
    block_size: int = CURRENT_BLOCK_BYTES,
) -> bool:


    footer = shard.footer
    hmac_key = decrypt_aligned(
        footer.encrypted_hmac_key,
        stream_key,
        derive_key_manager_iv(stream_salt, hmac_key_block_key(shard.index), block_size),
    )
    computed = compute_shard_hmac(shard.index, footer.salt, ciphertext, hmac_key)
    encrypted_computed = encrypt_aligned(
        computed,
        stream_key,
        derive_key_manager_iv(stream_salt, hmac_value_block_key(shard.index), block_size),
    )
    return hmac.compare_digest(encrypted_computed, footer.hmac_value)


def decrypt_shard_unauthenticated(
    shard: ProtectedStreamShard,
    ciphertext: bytes,
    stream_key: bytes,
    stream_salt: bytes,
    *,
    block_size: int = CURRENT_BLOCK_BYTES,
) -> bytes:


    content_iv = derive_key_manager_iv(
        stream_salt,
        content_block_key(shard.footer.salt, shard.index),
        block_size,
    )
    decrypted = decrypt_aligned(ciphertext, stream_key, content_iv)
    if shard.inner_padding_size:
        decrypted = decrypted[: -shard.inner_padding_size]
    return decrypted


def encrypt_shard_for_fixture(
    plaintext_shard: bytes,
    shard_index: int,
    footer_salt: int,
    session_id: int,
    hmac_key: bytes,
    stream_key: bytes,
    stream_salt: bytes,
    *,
    block_size: int = CURRENT_BLOCK_BYTES,
) -> tuple[bytes, bytes]:


    if len(plaintext_shard) % block_size:
        raise ValueError("plaintext shard must already include inner padding")
    ciphertext = encrypt_aligned(
        plaintext_shard,
        stream_key,
        derive_key_manager_iv(
            stream_salt, content_block_key(footer_salt, shard_index), block_size
        ),
    )
    encrypted_key = encrypt_aligned(
        hmac_key,
        stream_key,
        derive_key_manager_iv(stream_salt, hmac_key_block_key(shard_index), block_size),
    )
    encrypted_value = encrypt_aligned(
        compute_shard_hmac(shard_index, footer_salt, ciphertext, hmac_key),
        stream_key,
        derive_key_manager_iv(stream_salt, hmac_value_block_key(shard_index), block_size),
    )
    footer = build_protected_footer(session_id, footer_salt, encrypted_key, encrypted_value)
    return ciphertext, footer


def _hex_bytes(value: str, label: str) -> bytes:
    try:
        return bytes.fromhex(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError(f"invalid {label} hex: {error}") from error


def main() -> int:
    parser = argparse.ArgumentParser(
        description="validate, inventory, and optionally decrypt a Syzygy protected stream"
    )
    parser.add_argument("stream", type=Path)
    parser.add_argument(
        "--block-size",
        type=lambda value: int(value, 0),
        required=True,
        help="IMsoCryptSession block size (decimal or 0x-prefixed)",
    )
    parser.add_argument("--key-hex", help="unwrapped random stream AES key")
    parser.add_argument("--stream-salt-hex", help="keyData saltValue")
    parser.add_argument("--output", type=Path, help="write authenticated plaintext")
    parser.add_argument(
        "--session-id",
        type=lambda value: int(value, 0),
        help="expected footer session ID",
    )
    args = parser.parse_args()
    try:
        data = args.stream.read_bytes()
        layout = inspect_protected_stream(data, args.block_size)
        decrypt_options = (args.key_hex, args.stream_salt_hex, args.output)
        if any(option is not None for option in decrypt_options):
            if not all(option is not None for option in decrypt_options):
                parser.error(
                    "--key-hex, --stream-salt-hex, and --output are required together"
                )
            plaintext = authenticate_and_decrypt_protected_stream(
                data,
                _hex_bytes(args.key_hex, "key"),
                _hex_bytes(args.stream_salt_hex, "stream salt"),
                block_size=args.block_size,
                expected_session_id=args.session_id,
            )
            args.output.write_bytes(plaintext)
    except (OSError, ProtectedStreamDecodeError, ValueError) as error:
        parser.error(str(error))
    print(json.dumps(layout.to_json_dict(), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
