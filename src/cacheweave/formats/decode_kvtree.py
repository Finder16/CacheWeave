

from __future__ import annotations

import argparse
import json
import struct
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import lz4.frame

from .terse_codec import TerseDecodeError, TerseReader, zigzag_decode


KVTREE_MAGIC = 0x69

KEY_TYPES = {
    0: "vector<uint8>",
    1: "vector<uint16>",
    2: "vector<uint32>",
    3: "vector<uint64>",
    4: "array<uint8,16>",
    5: "wstring",
    6: "string",
    7: "guid",
    8: "uint8",
    9: "uint16",
    10: "uint32",
    11: "uint64",
}

VALUE_TYPES = {
    0: "NotSet",
    1: "bool",
    2: "vector<uint8>",
    3: "vector<uint16>",
    4: "vector<uint32>",
    5: "vector<uint64>",
    6: "vector<int16>",
    7: "vector<int32>",
    8: "vector<int64>",
    9: "array<uint8,16>",
    10: "guid",
    11: "uint8",
    12: "uint16",
    13: "uint32",
    14: "uint64",
    15: "int16",
    16: "int32",
    17: "int64",
    18: "string",
    19: "wstring",
    20: "Binary",
}


class KVTreeDecodeError(ValueError):
    pass


@dataclass(frozen=True)
class TypedValue:
    type_id: int
    type_name: str
    value: Any

    def to_json_dict(self) -> dict[str, Any]:
        value = self.value.hex() if isinstance(self.value, bytes) else self.value
        return {"type_id": self.type_id, "type_name": self.type_name, "value": value}


@dataclass(frozen=True)
class KVNode:
    key: TypedValue
    value: TypedValue
    children: tuple["KVNode", ...]
    serialized_tag: int

    def to_json_dict(self) -> dict[str, Any]:
        return {
            "key": self.key.to_json_dict(),
            "value": self.value.to_json_dict(),
            "serialized_tag": f"0x{self.serialized_tag:02x}",
            "children": [child.to_json_dict() for child in self.children],
        }


@dataclass(frozen=True)
class KVTree:
    children: tuple[KVNode, ...]
    decoded_size: int
    compressed_size: int

    def to_json_dict(self) -> dict[str, Any]:
        return {
            "decoded_size": self.decoded_size,
            "compressed_size": self.compressed_size,
            "root_child_count": len(self.children),
            "children": [child.to_json_dict() for child in self.children],
        }


class _KVReader(TerseReader):
    def read_string(self) -> str:
        count = self.read_uleb128(32)
        raw = self.read_exact(count)
        try:
            return raw.decode("utf-8", errors="strict")
        except UnicodeDecodeError:

            return raw.decode("latin-1")

    def read_unsigned_span(self, bits: int) -> Any:
        count = self.read_uleb128(32)
        if bits == 8:
            return self.read_exact(count)
        return [self.read_uleb128(bits) for _ in range(count)]

    def read_signed_span(self, bits: int) -> list[int]:
        count = self.read_uleb128(32)
        return [zigzag_decode(self.read_uleb128(bits), bits) for _ in range(count)]


def _guid_value(raw: bytes) -> dict[str, str]:
    return {"guid": str(uuid.UUID(bytes_le=raw)), "raw_hex": raw.hex()}


def _read_key(reader: _KVReader) -> TypedValue:
    type_id = reader.read_uleb128(8)
    type_name = KEY_TYPES.get(type_id)
    if type_name is None:
        raise KVTreeDecodeError(f"unknown key type {type_id}")
    if type_id <= 3:
        value = reader.read_unsigned_span((8, 16, 32, 64)[type_id])
    elif type_id == 4:
        value = reader.read_exact(16)
    elif type_id == 5:
        value = reader.read_wstring()
    elif type_id == 6:
        value = reader.read_string()
    elif type_id == 7:
        value = _guid_value(reader.read_exact(16))
    elif type_id == 8:
        value = reader.read_exact(1)[0]
    else:
        value = reader.read_uleb128((16, 32, 64)[type_id - 9])
    return TypedValue(type_id, type_name, value)


_COMPACT_VALUES: dict[int, tuple[int, Any]] = {
    0x15: (1, True),
    0x16: (1, False),
    0x17: (2, b""),
    0x18: (3, []),
    0x19: (4, []),
    0x1A: (5, []),
    0x1C: (6, []),
    0x1D: (7, []),
    0x1E: (8, []),
    0x20: (10, {"guid": str(uuid.UUID(int=0)), "raw_hex": "00" * 16}),
    0x21: (11, 0),
    0x22: (12, 0),
    0x23: (13, 0),
    0x24: (14, 0),
    0x25: (15, 0),
    0x26: (16, 0),
    0x27: (17, 0),
    0x28: (18, ""),
    0x29: (19, ""),
}


def _normalize_tag(serialized_tag: int) -> tuple[int, bool, int | None]:
    if serialized_tag >= 0x70:
        has_subtree = serialized_tag >= 0xB6
        adjusted = serialized_tag - 0x46 if has_subtree else serialized_tag
        binary_length = adjusted - 0x70
        if not 0 <= binary_length <= 0x45:
            raise KVTreeDecodeError(
                f"invalid inline Binary tag 0x{serialized_tag:02x}"
            )
        return 20, has_subtree, binary_length
    has_subtree = serialized_tag >= 0x46
    normalized = serialized_tag - 0x46 if has_subtree else serialized_tag
    return normalized, has_subtree, None


def _read_value(reader: _KVReader, serialized_tag: int) -> tuple[TypedValue, bool]:
    normalized, has_subtree, binary_length = _normalize_tag(serialized_tag)
    if binary_length is not None:
        return TypedValue(20, VALUE_TYPES[20], reader.read_exact(binary_length)), has_subtree
    if normalized in _COMPACT_VALUES:
        type_id, value = _COMPACT_VALUES[normalized]
        return TypedValue(type_id, VALUE_TYPES[type_id], value), has_subtree
    type_name = VALUE_TYPES.get(normalized)
    if type_name is None:
        raise KVTreeDecodeError(
            f"unknown normalized value tag 0x{normalized:02x} "
            f"(serialized 0x{serialized_tag:02x})"
        )
    if normalized == 0:
        value: Any = None
    elif normalized == 1:
        value = reader.read_bool()
    elif 2 <= normalized <= 5:
        value = reader.read_unsigned_span((8, 16, 32, 64)[normalized - 2])
    elif 6 <= normalized <= 8:
        value = reader.read_signed_span((16, 32, 64)[normalized - 6])
    elif normalized == 9:
        value = reader.read_exact(16)
    elif normalized == 10:
        value = _guid_value(reader.read_exact(16))
    elif normalized == 11:
        value = reader.read_exact(1)[0]
    elif 12 <= normalized <= 14:
        value = reader.read_uleb128((16, 32, 64)[normalized - 12])
    elif 15 <= normalized <= 17:
        bits = (16, 32, 64)[normalized - 15]
        value = zigzag_decode(reader.read_uleb128(bits), bits)
    elif normalized == 18:
        value = reader.read_string()
    elif normalized == 19:
        value = reader.read_wstring()
    else:
        raise KVTreeDecodeError(
            "direct Binary tag 0x14 has no recovered length encoding; current "
            "writer uses inline tags 0x70..0xb5"
        )
    return TypedValue(normalized, type_name, value), has_subtree


def _decompress_frame(frame: bytes, max_decoded_size: int) -> bytes:
    if max_decoded_size <= 0:
        raise ValueError("max_decoded_size must be positive")
    decompressor = lz4.frame.LZ4FrameDecompressor()
    try:
        output = bytearray(
            decompressor.decompress(frame, max_length=max_decoded_size + 1)
        )
        while not decompressor.eof and not decompressor.needs_input:
            remaining = max_decoded_size + 1 - len(output)
            if remaining <= 0:
                break
            output.extend(decompressor.decompress(b"", max_length=remaining))
    except RuntimeError as error:
        raise KVTreeDecodeError(f"invalid LZ4 frame: {error}") from error
    if len(output) > max_decoded_size:
        raise KVTreeDecodeError(
            f"decoded payload exceeds {max_decoded_size} byte safety limit"
        )
    if not decompressor.eof:
        if decompressor.needs_input:
            raise KVTreeDecodeError("truncated LZ4 frame")
        raise KVTreeDecodeError(
            f"decoded payload exceeds {max_decoded_size} byte safety limit"
        )
    if decompressor.unused_data:
        raise KVTreeDecodeError(
            f"{len(decompressor.unused_data)} bytes follow the LZ4 frame"
        )
    return bytes(output)


def decode_payload(
    payload: bytes,
    *,
    max_nodes: int = 1_000_000,
    max_depth: int = 256,
) -> tuple[KVNode, ...]:
    reader = _KVReader(payload)
    node_count = 0

    def read_children(count: int, depth: int) -> tuple[KVNode, ...]:
        nonlocal node_count
        if depth > max_depth:
            raise KVTreeDecodeError(f"tree depth exceeds {max_depth}")
        if count > max_nodes - node_count:
            raise KVTreeDecodeError(f"node count exceeds {max_nodes}")
        children: list[KVNode] = []
        for _ in range(count):
            node_count += 1
            key = _read_key(reader)


            serialized_tag = reader.read_exact(1)[0]
            value, has_subtree = _read_value(reader, serialized_tag)
            grandchild_count = reader.read_uleb128(32) if has_subtree else 0
            grandchildren = read_children(grandchild_count, depth + 1)
            children.append(KVNode(key, value, grandchildren, serialized_tag))
        return tuple(children)

    try:
        root_count = reader.read_uleb128(32)
        children = read_children(root_count, 0)
    except TerseDecodeError as error:
        raise KVTreeDecodeError(str(error)) from error
    if not reader.finished:
        raise KVTreeDecodeError(f"{reader.remaining} trailing decoded bytes")
    return children


def decode_kvtree(
    data: bytes,
    *,
    max_decoded_size: int = 256 * 1024 * 1024,
    max_nodes: int = 1_000_000,
    max_depth: int = 256,
) -> KVTree:
    if not data or data[0] != KVTREE_MAGIC:
        raise KVTreeDecodeError("serialized KVTree must begin with magic byte 0x69")
    if len(data) == 1:
        raise KVTreeDecodeError("missing LZ4 frame after KVTree magic")
    payload = _decompress_frame(data[1:], max_decoded_size)
    children = decode_payload(payload, max_nodes=max_nodes, max_depth=max_depth)
    return KVTree(children, len(payload), len(data) - 1)


def _main() -> int:
    parser = argparse.ArgumentParser(description="decode an Office Storage::KeyValueTree")
    parser.add_argument("path", type=Path)
    parser.add_argument("--max-decoded-size", type=int, default=256 * 1024 * 1024)
    parser.add_argument("--max-nodes", type=int, default=1_000_000)
    parser.add_argument("--max-depth", type=int, default=256)
    args = parser.parse_args()
    try:
        tree = decode_kvtree(
            args.path.read_bytes(),
            max_decoded_size=args.max_decoded_size,
            max_nodes=args.max_nodes,
            max_depth=args.max_depth,
        )
        print(json.dumps(tree.to_json_dict(), indent=2, ensure_ascii=False))
    except (OSError, KVTreeDecodeError) as error:
        parser.error(str(error))
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
