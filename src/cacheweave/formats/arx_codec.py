

from __future__ import annotations

import argparse
import json
from dataclasses import asdict, dataclass, replace
from pathlib import Path, PureWindowsPath
from typing import Iterable

import lz4.frame

from .decode_kvtree import KVTree, KVTreeDecodeError, decode_kvtree
from .terse_codec import TerseDecodeError, TerseReader, decode_envelope


UINT64_MAX = (1 << 64) - 1
ARX_BLOCK_SIZE = 0x1000
ARX_SUPERBLOCK_ROOT_OFFSET = 0
ARX_SUPERBLOCK_ROOT_LENGTH = 0x2000


class ArxDecodeError(ValueError):
    pass


@dataclass(frozen=True)
class Extent:


    offset: int
    length: int

    def __post_init__(self) -> None:
        for name, value in (("offset", self.offset), ("length", self.length)):
            if not 0 <= value <= UINT64_MAX:
                raise ValueError(f"{name} does not fit uint64")
        if self.offset + self.length > UINT64_MAX:
            raise ValueError("extent end exceeds uint64")

    @property
    def block_count(self) -> int:


        return self.length




ZIGZAG_ALLOCATOR_ROOT = Extent(0x2000, 0xC000)


@dataclass(frozen=True)
class FramedExtents:


    extents: tuple[Extent, ...]
    payload_size: int
    trailing: bytes

    def to_json_dict(self) -> dict[str, object]:
        return {
            "payload_size": self.payload_size,
            "extent_count": len(self.extents),
            "extents": [asdict(extent) for extent in self.extents],
            "trailing_size": len(self.trailing),
            "trailing_hex": self.trailing.hex(),
        }


@dataclass(frozen=True)
class ArxSuperblock:


    version: int
    allocator_version: int
    hash_algorithm: int
    generation: int
    file_index_version: int
    reserved_block_count: int
    feature_flags: int
    allocator_root_block: Extent
    file_index_root_block: Extent
    volume_id: bytes
    creation_time: int
    decoded_size: int
    compressed_size: int

    def to_json_dict(self) -> dict[str, object]:
        result = asdict(self)
        result["volume_id"] = self.volume_id.hex()
        return result


@dataclass(frozen=True)
class ArxSuperblockHalf:


    slot: int
    offset: int
    serialized_size: int
    superblock: ArxSuperblock | None
    error: str | None

    @property
    def valid(self) -> bool:
        return self.superblock is not None

    def to_json_dict(self) -> dict[str, object]:
        return {
            "slot": self.slot,
            "offset": self.offset,
            "slot_size": ARX_BLOCK_SIZE,
            "serialized_size": self.serialized_size,
            "valid": self.valid,
            "error": self.error,
            "superblock": (
                self.superblock.to_json_dict() if self.superblock is not None else None
            ),
        }


@dataclass(frozen=True)
class ArxPhysicalVolumeSuperblocks:


    halves: tuple[ArxSuperblockHalf, ArxSuperblockHalf]
    selected_slot: int
    selected: ArxSuperblock
    volume_size: int

    def to_json_dict(self) -> dict[str, object]:
        return {
            "root_extent": {
                "offset": ARX_SUPERBLOCK_ROOT_OFFSET,
                "length": ARX_SUPERBLOCK_ROOT_LENGTH,
            },
            "volume_size": self.volume_size,
            "selected_slot": self.selected_slot,
            "selected_generation": self.selected.generation,
            "selected": self.selected.to_json_dict(),
            "halves": [half.to_json_dict() for half in self.halves],
        }


@dataclass(frozen=True)
class HashDirectoryEntry:


    slot: int
    extent: Extent


@dataclass(frozen=True)
class ArxHashDirectory:


    version: int
    depth: int
    generation: int
    entries: tuple[HashDirectoryEntry, ...]
    decoded_size: int
    compressed_size: int

    def to_json_dict(self) -> dict[str, object]:
        return {
            "version": self.version,
            "depth": self.depth,
            "generation": self.generation,
            "entry_count": len(self.entries),
            "entries": [
                {"slot": entry.slot, "extent": asdict(entry.extent)}
                for entry in self.entries
            ],
            "decoded_size": self.decoded_size,
            "compressed_size": self.compressed_size,
        }

    def bucket(self, slot: int) -> Extent:


        if not 0 <= slot < len(self.entries):
            raise IndexError(slot)
        return self.entries[slot].extent

    def local_depth(self, slot: int) -> int:


        extent = self.bucket(slot)
        references = sum(entry.extent == extent for entry in self.entries)
        if references <= 0 or references & (references - 1):
            raise ArxDecodeError(
                f"bucket reference count {references} is not a power of two"
            )
        return self.depth - (references.bit_length() - 1)


@dataclass(frozen=True)
class BucketFileRecord:


    name: str
    name_hash: int
    syzygy_key: bytes | None
    deleted: bool
    file_attributes: int
    size: int
    creation_time_delta: int
    last_access_time_delta: int
    last_write_time_delta: int
    creation_time: int | None
    last_access_time: int | None
    last_write_time: int | None
    extents: tuple[Extent, ...]
    terse_checksum: int
    serialized_size: int

    def to_json_dict(self) -> dict[str, object]:
        result = asdict(self)
        result["syzygy_key"] = (
            None if self.syzygy_key is None else self.syzygy_key.hex()
        )
        result["terse_checksum"] = f"0x{self.terse_checksum:08x}"
        return result


@dataclass(frozen=True)
class ArxBucket:
    version: int
    files: tuple[BucketFileRecord, ...]
    decoded_size: int
    compressed_size: int

    def to_json_dict(self) -> dict[str, object]:
        return {
            "version": self.version,
            "file_count": len(self.files),
            "live_file_count": sum(not item.deleted for item in self.files),
            "files": [item.to_json_dict() for item in self.files],
            "decoded_size": self.decoded_size,
            "compressed_size": self.compressed_size,
        }


@dataclass(frozen=True)
class MonolithicFileRecord:


    name: str
    extents: tuple[Extent, ...]
    file_attributes: int
    creation_time: int
    last_access_time: int
    last_write_time: int
    size: int

    def to_json_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "extent_count": len(self.extents),
            "extents": [asdict(extent) for extent in self.extents],
            "file_attributes": self.file_attributes,
            "creation_time": self.creation_time,
            "last_access_time": self.last_access_time,
            "last_write_time": self.last_write_time,
            "size": self.size,
        }


@dataclass(frozen=True)
class ArxMonolithicFileIndex:
    files: tuple[MonolithicFileRecord, ...]
    decoded_size: int
    compressed_size: int

    def to_json_dict(self) -> dict[str, object]:
        return {
            "file_count": len(self.files),
            "files": [item.to_json_dict() for item in self.files],
            "decoded_size": self.decoded_size,
            "compressed_size": self.compressed_size,
        }


@dataclass(frozen=True)
class ArxNextGenAllocatorState:


    version: int
    generation: int
    pinned_file_index_generation: int
    pinned_file_index_root: Extent
    physical_volume_size: int
    freeze_active: bool
    minimum_allocatable_offset: int
    free_list: tuple[Extent, ...]
    indirection_depth: int
    root_leaf_pointers: tuple[Extent, ...]
    frozen_list: tuple[Extent, ...]
    decoded_size: int
    compressed_size: int

    def to_json_dict(self) -> dict[str, object]:
        result = asdict(self)
        result["pinned_file_index_root"] = asdict(self.pinned_file_index_root)
        result["free_list"] = [asdict(extent) for extent in self.free_list]
        result["root_leaf_pointers"] = [
            asdict(extent) for extent in self.root_leaf_pointers
        ]
        result["frozen_list"] = [asdict(extent) for extent in self.frozen_list]
        return result


@dataclass(frozen=True)
class ArxNextGenAllocatorHalf:
    slot: int
    offset: int
    serialized_size: int
    state: ArxNextGenAllocatorState | None
    error: str | None

    @property
    def valid(self) -> bool:
        return self.state is not None

    def to_json_dict(self) -> dict[str, object]:
        return {
            "slot": self.slot,
            "offset": self.offset,
            "serialized_size": self.serialized_size,
            "valid": self.valid,
            "error": self.error,
            "state": self.state.to_json_dict() if self.state is not None else None,
        }


@dataclass(frozen=True)
class ArxNextGenAllocatorRoot:
    extent: Extent
    halves: tuple[ArxNextGenAllocatorHalf, ArxNextGenAllocatorHalf]
    selected_slot: int
    selected: ArxNextGenAllocatorState
    tree_block_extents: tuple[Extent, ...]
    spilled_free_list: tuple[Extent, ...]

    def to_json_dict(self) -> dict[str, object]:
        return {
            "extent": asdict(self.extent),
            "selected_slot": self.selected_slot,
            "selected_generation": self.selected.generation,
            "selected": self.selected.to_json_dict(),
            "tree_block_count": len(self.tree_block_extents),
            "tree_block_extents": [
                asdict(extent) for extent in self.tree_block_extents
            ],
            "spilled_free_extent_count": len(self.spilled_free_list),
            "spilled_free_list": [
                asdict(extent) for extent in self.spilled_free_list
            ],
            "halves": [half.to_json_dict() for half in self.halves],
        }


@dataclass(frozen=True)
class ArxHashDirectoryHalf:
    slot: int
    offset: int
    serialized_size: int
    directory: ArxHashDirectory | None
    error: str | None

    @property
    def valid(self) -> bool:
        return self.directory is not None

    def to_json_dict(self) -> dict[str, object]:
        return {
            "slot": self.slot,
            "offset": self.offset,
            "serialized_size": self.serialized_size,
            "valid": self.valid,
            "error": self.error,
            "directory": (
                self.directory.to_json_dict() if self.directory is not None else None
            ),
        }


@dataclass(frozen=True)
class ArxBucketSnapshot:
    extent: Extent
    directory_slots: tuple[int, ...]
    serialized_size: int
    bucket: ArxBucket

    def to_json_dict(self) -> dict[str, object]:
        return {
            "extent": asdict(self.extent),
            "directory_slots": list(self.directory_slots),
            "serialized_size": self.serialized_size,
            "bucket": self.bucket.to_json_dict(),
        }


@dataclass(frozen=True)
class ArxExtendibleFileIndexSnapshot:
    extent: Extent
    halves: tuple[ArxHashDirectoryHalf, ArxHashDirectoryHalf]
    selected_slot: int
    selected: ArxHashDirectory
    buckets: tuple[ArxBucketSnapshot, ...]

    def to_json_dict(self) -> dict[str, object]:
        return {
            "extent": asdict(self.extent),
            "selected_slot": self.selected_slot,
            "selected_generation": self.selected.generation,
            "selected": self.selected.to_json_dict(),
            "halves": [half.to_json_dict() for half in self.halves],
            "unique_bucket_count": len(self.buckets),
            "buckets": [bucket.to_json_dict() for bucket in self.buckets],
        }


@dataclass(frozen=True)
class ArxPhysicalVolume:
    superblocks: ArxPhysicalVolumeSuperblocks
    allocator: ArxNextGenAllocatorRoot
    file_index_root: Extent
    file_index_kind: str
    monolithic_file_index: ArxMonolithicFileIndex | None
    extendible_file_index: ArxExtendibleFileIndexSnapshot | None

    def to_json_dict(self) -> dict[str, object]:
        return {
            "volume_size": self.superblocks.volume_size,
            "superblocks": self.superblocks.to_json_dict(),
            "allocator": self.allocator.to_json_dict(),
            "file_index": {
                "kind": self.file_index_kind,
                "root_extent": asdict(self.file_index_root),
                "monolithic": (
                    self.monolithic_file_index.to_json_dict()
                    if self.monolithic_file_index is not None
                    else None
                ),
                "extendible": (
                    self.extendible_file_index.to_json_dict()
                    if self.extendible_file_index is not None
                    else None
                ),
            },
        }


_SYZYGY_BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
_SYZYGY_SUFFIXES = {0: ".P", 1: ".R", 2: ".UR"}
_SYZYGY_SUFFIX_TO_KIND = {suffix: kind for kind, suffix in _SYZYGY_SUFFIXES.items()}


class _RawReader:


    def __init__(self, data: bytes | bytearray | memoryview) -> None:
        self._data = memoryview(data).cast("B")
        self._offset = 0

    @property
    def remaining(self) -> int:
        return len(self._data) - self._offset

    @property
    def finished(self) -> bool:
        return self._offset == len(self._data)

    def read(self, size: int) -> bytes:
        if size < 0:
            raise ValueError("size must be nonnegative")
        end = self._offset + size
        if end > len(self._data):
            raise ArxDecodeError(
                f"truncated raw payload: need {size} bytes, have {self.remaining}"
            )
        result = self._data[self._offset:end].tobytes()
        self._offset = end
        return result

    def uint(self, size: int) -> int:
        return int.from_bytes(self.read(size), "little")

    def vector(self, *, max_size: int) -> bytes:
        size = self.uint(4)
        if size > max_size:
            raise ArxDecodeError(f"vector size {size} exceeds limit {max_size}")
        return self.read(size)

    def wstring(self, *, max_code_units: int) -> str:
        count = self.uint(4)
        if count > max_code_units:
            raise ArxDecodeError(
                f"wide-string length {count} exceeds limit {max_code_units}"
            )
        raw = self.read(count * 2)
        try:
            return raw.decode("utf-16le")
        except UnicodeDecodeError as error:
            raise ArxDecodeError(f"invalid UTF-16LE file name: {error}") from error


def _decompress_storage_frame(data: bytes, *, max_decoded_size: int) -> bytes:


    if max_decoded_size <= 0:
        raise ValueError("max_decoded_size must be positive")
    decompressor = lz4.frame.LZ4FrameDecompressor()
    try:
        output = bytearray(
            decompressor.decompress(data, max_length=max_decoded_size + 1)
        )
        while not decompressor.eof and not decompressor.needs_input:
            remaining = max_decoded_size + 1 - len(output)
            if remaining <= 0:
                break
            output.extend(decompressor.decompress(b"", max_length=remaining))
    except RuntimeError as error:
        raise ArxDecodeError(f"invalid Storage::Compression LZ4 frame: {error}") from error
    if len(output) > max_decoded_size:
        raise ArxDecodeError(
            f"decoded payload exceeds {max_decoded_size} byte safety limit"
        )
    if not decompressor.eof:
        if decompressor.needs_input:
            raise ArxDecodeError("truncated Storage::Compression LZ4 frame")
        raise ArxDecodeError(
            f"decoded payload exceeds {max_decoded_size} byte safety limit"
        )
    if decompressor.unused_data:
        raise ArxDecodeError(
            f"{len(decompressor.unused_data)} bytes follow the LZ4 frame"
        )
    return bytes(output)


def _extract_storage_frame_prefix(
    data: bytes,
    *,
    max_decoded_size: int,
    context: str,
) -> bytes:


    if max_decoded_size <= 0:
        raise ValueError("max_decoded_size must be positive")
    if not data:
        raise ArxDecodeError(f"{context} is empty")
    decompressor = lz4.frame.LZ4FrameDecompressor()
    output_size = 0
    try:
        chunk = decompressor.decompress(
            data, max_length=max_decoded_size + 1
        )
        output_size += len(chunk)
        while not decompressor.eof and not decompressor.needs_input:
            remaining = max_decoded_size + 1 - output_size
            if remaining <= 0:
                break
            output_size += len(decompressor.decompress(b"", max_length=remaining))
    except RuntimeError as error:
        raise ArxDecodeError(f"invalid {context} LZ4 frame: {error}") from error
    if output_size > max_decoded_size:
        raise ArxDecodeError(
            f"{context} decoded payload exceeds {max_decoded_size} bytes"
        )
    if not decompressor.eof:
        if decompressor.needs_input:
            raise ArxDecodeError(f"truncated {context} LZ4 frame")
        raise ArxDecodeError(f"{context} LZ4 decoder did not reach EOF")
    frame_size = len(data) - len(decompressor.unused_data)
    if frame_size <= 0:
        raise ArxDecodeError(f"{context} contains an empty LZ4 frame")
    return data[:frame_size]


def encode_syzygy_identifier(identifier: bytes) -> str:


    if len(identifier) != 16:
        raise ValueError("Syzygy identifier must contain exactly 16 bytes")
    low_first = "".join(
        _SYZYGY_BASE32_ALPHABET[value & 0x1F]
        + _SYZYGY_BASE32_ALPHABET[value >> 5]
        for value in identifier
    )
    return low_first[::-1]


def decode_syzygy_identifier(encoded: str) -> bytes:


    if len(encoded) != 32:
        raise ValueError("Syzygy identifier must contain 32 base32 characters")
    values = {character: index for index, character in enumerate(_SYZYGY_BASE32_ALPHABET)}
    low_first = encoded[::-1]
    raw = bytearray()
    try:
        for index in range(0, len(low_first), 2):
            low = values[low_first[index].upper()]
            high = values[low_first[index + 1].upper()]
            value = low | (high << 5)
            if value > 0xFF:
                raise ValueError("Syzygy base32 high digit exceeds three bits")
            raw.append(value)
    except KeyError as error:
        raise ValueError("invalid Syzygy base32 character") from error
    return bytes(raw)


def build_drg_namespace_path(
    root: str | PureWindowsPath,
    identifier: bytes,
    generation: int,
    *,
    major_version: int = 0,
) -> PureWindowsPath:


    if generation < 0:
        raise ValueError("generation must be non-negative")
    if major_version < 0:
        raise ValueError("major_version must be non-negative")
    return (
        PureWindowsPath(root)
        / str(major_version)
        / str(generation)
        / encode_syzygy_identifier(identifier)
    )


def encode_syzygy_file_name(identifier: bytes, kind: int) -> str:


    try:
        suffix = _SYZYGY_SUFFIXES[kind]
    except KeyError as error:
        raise ValueError("Syzygy kind must be 0, 1, or 2") from error
    return encode_syzygy_identifier(identifier) + suffix


def decode_syzygy_file_name(name: str) -> tuple[bytes, int]:
    suffix = next(
        (item for item in (".UR", ".P", ".R") if name.endswith(item)),
        None,
    )
    if suffix is None:
        raise ValueError("Syzygy file name must end in .P, .R, or .UR")
    encoded = name[: -len(suffix)]
    return decode_syzygy_identifier(encoded), _SYZYGY_SUFFIX_TO_KIND[suffix]


def _encode_uleb64(value: int) -> bytes:
    if not 0 <= value <= UINT64_MAX:
        raise ValueError("value does not fit uint64")
    result = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        result.append(byte | (0x80 if value else 0))
        if not value:
            return bytes(result)


def _reader(data: bytes | bytearray | memoryview) -> TerseReader:
    return TerseReader(data)


def _read_uleb64(reader: TerseReader) -> int:
    try:
        return reader.read_uleb128(64)
    except TerseDecodeError as error:
        raise ArxDecodeError(str(error)) from error


def _require_finished(reader: TerseReader) -> None:
    if not reader.finished:
        raise ArxDecodeError(f"{reader.remaining} trailing payload bytes")


def _read_extent_count(reader: TerseReader, max_extents: int) -> int:
    if max_extents < 0:
        raise ValueError("max_extents must be nonnegative")
    count = _read_uleb64(reader)
    if count > max_extents:
        raise ArxDecodeError(f"extent count {count} exceeds limit {max_extents}")
    return count


def encode_block_runs(extents: Iterable[Extent]) -> bytes:


    items = tuple(extents)
    output = bytearray(_encode_uleb64(len(items)))
    previous_end = 0
    for index, extent in enumerate(items):
        if extent.offset < previous_end:
            raise ValueError(
                f"extent {index} starts before previous extent end {previous_end}"
            )
        output.extend(_encode_uleb64(extent.offset - previous_end))
        output.extend(_encode_uleb64(extent.length))
        previous_end = extent.offset + extent.length
    return bytes(output)


def decode_block_runs(
    data: bytes | bytearray | memoryview,
    *,
    max_extents: int = 1_000_000,
) -> tuple[Extent, ...]:


    reader = _reader(data)
    count = _read_extent_count(reader, max_extents)
    result: list[Extent] = []
    previous_end = 0
    for index in range(count):
        delta = _read_uleb64(reader)
        length = _read_uleb64(reader)
        if delta > UINT64_MAX - previous_end:
            raise ArxDecodeError(f"extent {index} offset overflows uint64")
        offset = previous_end + delta
        if length > UINT64_MAX - offset:
            raise ArxDecodeError(f"extent {index} end overflows uint64")
        result.append(Extent(offset, length))
        previous_end = offset + length
    _require_finished(reader)
    return tuple(result)


def encode_leaf_pointers(extents: Iterable[Extent]) -> bytes:


    items = tuple(extents)
    output = bytearray(_encode_uleb64(len(items)))
    for extent in items:
        output.extend(_encode_uleb64(extent.offset))
        output.extend(_encode_uleb64(extent.length))
    return bytes(output)


def decode_leaf_pointers(
    data: bytes | bytearray | memoryview,
    *,
    max_extents: int = 1_000_000,
) -> tuple[Extent, ...]:


    reader = _reader(data)
    count = _read_extent_count(reader, max_extents)
    result: list[Extent] = []
    for index in range(count):
        offset = _read_uleb64(reader)
        length = _read_uleb64(reader)
        if length > UINT64_MAX - offset:
            raise ArxDecodeError(f"extent {index} end overflows uint64")
        result.append(Extent(offset, length))
    _require_finished(reader)
    return tuple(result)


def encode_length_prefixed_payload(payload: bytes) -> bytes:


    return _encode_uleb64(len(payload)) + payload


def decode_length_prefixed_payload(
    data: bytes | bytearray | memoryview,
) -> tuple[bytes, bytes]:


    reader = _reader(data)
    payload_size = _read_uleb64(reader)
    if payload_size > reader.remaining:
        raise ArxDecodeError(
            f"declared payload size {payload_size} exceeds {reader.remaining} bytes"
        )
    try:
        payload = reader.read_exact(payload_size)
        trailing = reader.read_exact(reader.remaining)
    except TerseDecodeError as error:
        raise ArxDecodeError(str(error)) from error
    return payload, trailing


def encode_leaf_pointer_block(extents: Iterable[Extent]) -> bytes:
    return encode_length_prefixed_payload(encode_leaf_pointers(extents))


def decode_leaf_pointer_block(
    data: bytes | bytearray | memoryview,
    *,
    max_extents: int = 1_000_000,
) -> FramedExtents:
    payload, trailing = decode_length_prefixed_payload(data)
    extents = decode_leaf_pointers(payload, max_extents=max_extents)
    return FramedExtents(extents, len(payload), trailing)


def encode_block_run_block(extents: Iterable[Extent]) -> bytes:
    return encode_length_prefixed_payload(encode_block_runs(extents))


def decode_block_run_block(
    data: bytes | bytearray | memoryview,
    *,
    max_extents: int = 1_000_000,
) -> FramedExtents:
    payload, trailing = decode_length_prefixed_payload(data)
    extents = decode_block_runs(payload, max_extents=max_extents)
    return FramedExtents(extents, len(payload), trailing)


_SUPERBLOCK_SCHEMA = {
    0: (14, "version"),
    1: (14, "allocator_version"),
    2: (11, "hash_algorithm"),
    3: (14, "generation"),
    4: (14, "file_index_version"),
    5: (14, "reserved_block_count"),
    6: (14, "feature_flags"),
    7: (20, "allocator_root_block"),
    8: (20, "file_index_root_block"),
    9: (9, "volume_id"),
    10: (14, "creation_time"),
}


def _extent_from_binary(name: str, value: object) -> Extent:
    if not isinstance(value, bytes) or len(value) != 16:
        actual = len(value) if isinstance(value, bytes) else type(value).__name__
        raise ArxDecodeError(f"{name} must be a 16-byte Binary value, got {actual}")
    return Extent(
        int.from_bytes(value[:8], "little"),
        int.from_bytes(value[8:], "little"),
    )


def decode_superblock_tree(tree: KVTree, *, volume_size: int | None = None) -> ArxSuperblock:


    values: dict[str, object] = {}
    seen_keys: set[int] = set()
    for node in tree.children:
        if node.children:
            raise ArxDecodeError("superblock root properties must not have subtrees")
        if node.key.type_id != 8 or not isinstance(node.key.value, int):
            raise ArxDecodeError("superblock keys must be uint8")
        key = node.key.value
        schema = _SUPERBLOCK_SCHEMA.get(key)
        if schema is None:
            raise ArxDecodeError(f"unknown superblock key {key}")
        if key in seen_keys:
            raise ArxDecodeError(f"duplicate superblock key {key}")
        seen_keys.add(key)
        expected_type, name = schema
        if node.value.type_id != expected_type:
            raise ArxDecodeError(
                f"superblock key {key} ({name}) has {node.value.type_name}, "
                f"expected value type id {expected_type}"
            )
        values[name] = node.value.value

    missing = sorted(set(_SUPERBLOCK_SCHEMA) - seen_keys)
    if missing:
        raise ArxDecodeError(f"missing superblock keys: {', '.join(map(str, missing))}")

    allocator_root = _extent_from_binary(
        "allocator_root_block", values["allocator_root_block"]
    )
    file_index_root = _extent_from_binary(
        "file_index_root_block", values["file_index_root_block"]
    )
    volume_id = values["volume_id"]
    if not isinstance(volume_id, bytes) or len(volume_id) != 16:
        raise ArxDecodeError("volume_id must be array<uint8,16>")
    reserved = int(values["reserved_block_count"])
    if reserved < 2:
        raise ArxDecodeError("reserved_block_count is below the verified minimum 2")
    for name, extent in (
        ("allocator_root_block", allocator_root),
        ("file_index_root_block", file_index_root),
    ):
        if extent.offset < 2:
            raise ArxDecodeError(f"{name} offset is below the verified minimum 2")
    if volume_size is not None:
        if volume_size < 0:
            raise ValueError("volume_size must be nonnegative")
        volume_block_count = volume_size >> 12
        if reserved > volume_block_count:
            raise ArxDecodeError("reserved_block_count exceeds 4 KiB volume blocks")
        for name, extent in (
            ("allocator_root_block", allocator_root),
            ("file_index_root_block", file_index_root),
        ):




            if extent.offset + extent.length > volume_size:
                raise ArxDecodeError(f"{name} exceeds the physical volume size")

    return ArxSuperblock(
        version=int(values["version"]),
        allocator_version=int(values["allocator_version"]),
        hash_algorithm=int(values["hash_algorithm"]),
        generation=int(values["generation"]),
        file_index_version=int(values["file_index_version"]),
        reserved_block_count=reserved,
        feature_flags=int(values["feature_flags"]),
        allocator_root_block=allocator_root,
        file_index_root_block=file_index_root,
        volume_id=volume_id,
        creation_time=int(values["creation_time"]),
        decoded_size=tree.decoded_size,
        compressed_size=tree.compressed_size,
    )


def decode_superblock(
    data: bytes,
    *,
    volume_size: int | None = None,
    max_decoded_size: int = 16 * 1024 * 1024,
) -> ArxSuperblock:
    try:
        tree = decode_kvtree(data, max_decoded_size=max_decoded_size, max_nodes=64)
    except KVTreeDecodeError as error:
        raise ArxDecodeError(str(error)) from error
    return decode_superblock_tree(tree, volume_size=volume_size)


def _extract_kvtree_from_zigzag_half(
    half: bytes,
    *,
    max_decoded_size: int,
    context: str = "Superblock half",
) -> bytes:


    if not half or half[0] != 0x69:
        actual = "empty" if not half else f"0x{half[0]:02x}"
        raise ArxDecodeError(f"{context} has {actual} instead of KVTree magic 0x69")
    if len(half) < 2:
        raise ArxDecodeError(f"{context} is missing its LZ4 frame")
    frame = _extract_storage_frame_prefix(
        half[1:],
        max_decoded_size=max_decoded_size,
        context=context,
    )
    return b"\x69" + frame


def decode_physical_volume_superblocks(
    data: bytes,
    *,
    volume_size: int | None = None,
    max_decoded_size: int = 16 * 1024 * 1024,
) -> ArxPhysicalVolumeSuperblocks:


    if len(data) < ARX_SUPERBLOCK_ROOT_LENGTH:
        raise ArxDecodeError(
            "physical volume capture is shorter than the fixed 0x2000-byte "
            "Superblock extent"
        )
    if volume_size is None:
        volume_size = len(data)
    if volume_size < 0:
        raise ValueError("volume_size must be nonnegative")

    halves: list[ArxSuperblockHalf] = []
    for slot in range(2):
        offset = ARX_SUPERBLOCK_ROOT_OFFSET + slot * ARX_BLOCK_SIZE
        raw_half = data[offset : offset + ARX_BLOCK_SIZE]
        serialized_size = 0
        try:
            encoded = _extract_kvtree_from_zigzag_half(
                raw_half, max_decoded_size=max_decoded_size
            )
            serialized_size = len(encoded)
            superblock = decode_superblock(
                encoded,
                volume_size=volume_size,
                max_decoded_size=max_decoded_size,
            )
            halves.append(
                ArxSuperblockHalf(slot, offset, serialized_size, superblock, None)
            )
        except ArxDecodeError as error:
            halves.append(
                ArxSuperblockHalf(slot, offset, serialized_size, None, str(error))
            )

    valid = [half for half in halves if half.superblock is not None]
    if not valid:
        details = "; ".join(
            f"slot {half.slot}: {half.error}" for half in halves
        )
        raise ArxDecodeError(f"neither Superblock generation is valid ({details})")

    selected = max(valid, key=lambda half: (half.superblock.generation, half.slot))
    assert selected.superblock is not None
    return ArxPhysicalVolumeSuperblocks(
        (halves[0], halves[1]),
        selected.slot,
        selected.superblock,
        volume_size,
    )


def decode_hash_directory_tree(
    tree: KVTree,
    *,
    volume_size: int | None = None,
) -> ArxHashDirectory:


    if volume_size is not None and volume_size < 0:
        raise ValueError("volume_size must be nonnegative")

    root: dict[int, object] = {}
    entries_node = None
    for node in tree.children:
        if node.key.type_id != 8 or not isinstance(node.key.value, int):
            raise ArxDecodeError("hash-directory root keys must be uint8")
        key = node.key.value
        if key not in (0, 1, 2, 3):
            raise ArxDecodeError(f"unknown hash-directory root key {key}")
        if key in root:
            raise ArxDecodeError(f"duplicate hash-directory root key {key}")
        root[key] = node
        if key == 2:
            entries_node = node

    missing = sorted({0, 1, 2, 3} - set(root))
    if missing:
        raise ArxDecodeError(
            f"missing hash-directory keys: {', '.join(map(str, missing))}"
        )

    version_node = root[0]
    depth_node = root[1]
    generation_node = root[3]
    assert entries_node is not None
    if version_node.children or version_node.value.type_id != 11:
        raise ArxDecodeError("hash-directory version must be a uint8 leaf")
    version = int(version_node.value.value)
    if version != 0:
        raise ArxDecodeError(f"unsupported hash-directory version {version}")
    if depth_node.children or depth_node.value.type_id != 11:
        raise ArxDecodeError("hash-directory depth must be a uint8 leaf")
    depth = int(depth_node.value.value)
    if not 1 <= depth <= 21:
        raise ArxDecodeError("hash-directory depth must be in the range 1..21")
    if generation_node.children or generation_node.value.type_id != 14:
        raise ArxDecodeError("hash-directory generation must be a uint64 leaf")
    if entries_node.value.type_id != 0 or entries_node.value.value is not None:
        raise ArxDecodeError("hash-directory entries value must be NotSet")

    expected_count = 1 << depth
    if len(entries_node.children) != expected_count:
        raise ArxDecodeError(
            f"hash-directory has {len(entries_node.children)} entries; "
            f"expected {expected_count} for depth {depth}"
        )

    by_slot: dict[int, HashDirectoryEntry] = {}
    for node in entries_node.children:
        if node.children:
            raise ArxDecodeError("hash-directory entries must not have subtrees")
        if node.key.type_id != 10 or not isinstance(node.key.value, int):
            raise ArxDecodeError("hash-directory entry keys must be uint32")
        slot = node.key.value
        if not 0 <= slot < expected_count:
            raise ArxDecodeError(f"hash-directory slot {slot} is out of range")
        if slot in by_slot:
            raise ArxDecodeError(f"duplicate hash-directory slot {slot}")
        extent = _extent_from_binary(f"hash-directory slot {slot}", node.value.value)
        if node.value.type_id != 20:
            raise ArxDecodeError(
                f"hash-directory slot {slot} must contain a Binary extent"
            )

        if extent.offset < 0x2000 or extent.offset & 0xFFF:
            raise ArxDecodeError(
                f"hash-directory slot {slot} offset is not a valid aligned byte offset"
            )
        if not 0x1000 <= extent.length <= 0x10000:
            raise ArxDecodeError(
                f"hash-directory slot {slot} length is outside 4096..65536 bytes"
            )
        if extent.length & 0xFFF:
            raise ArxDecodeError(
                f"hash-directory slot {slot} length is not 4-KiB aligned"
            )
        if volume_size is not None and extent.offset + extent.length > volume_size:
            raise ArxDecodeError(f"hash-directory slot {slot} exceeds the volume")
        by_slot[slot] = HashDirectoryEntry(slot, extent)

    expected_slots = set(range(expected_count))
    if set(by_slot) != expected_slots:
        missing_slots = sorted(expected_slots - set(by_slot))
        raise ArxDecodeError(
            f"hash-directory is missing slots: {', '.join(map(str, missing_slots[:8]))}"
        )

    return ArxHashDirectory(
        version=version,
        depth=depth,
        generation=int(generation_node.value.value),
        entries=tuple(by_slot[index] for index in range(expected_count)),
        decoded_size=tree.decoded_size,
        compressed_size=tree.compressed_size,
    )


def decode_hash_directory(
    data: bytes,
    *,
    volume_size: int | None = None,
    max_decoded_size: int = 256 * 1024 * 1024,
) -> ArxHashDirectory:
    try:
        tree = decode_kvtree(
            data,
            max_decoded_size=max_decoded_size,
            max_nodes=(1 << 21) + 4,
            max_depth=2,
        )
    except KVTreeDecodeError as error:
        raise ArxDecodeError(str(error)) from error
    return decode_hash_directory_tree(tree, volume_size=volume_size)


def _absolute_filetime(base: int | None, delta: int, field: str) -> int | None:
    if base is None:
        return None
    value = base + delta
    if not 0 <= value <= UINT64_MAX:
        raise ArxDecodeError(f"{field} FILETIME delta is outside uint64 range")
    return value


def decode_bucket_file_record(
    data: bytes,
    *,
    name: str,
    name_hash: int,
    syzygy_key: bytes | None = None,
    timestamp_base: int | None = None,
    max_extents: int = 0xFFFF,
) -> BucketFileRecord:


    if not 0 <= name_hash <= 0xFFFFFFFF:
        raise ValueError("name_hash must fit uint32")
    if timestamp_base is not None and not 0 <= timestamp_base <= UINT64_MAX:
        raise ValueError("timestamp_base must fit uint64")
    if max_extents < 0:
        raise ValueError("max_extents must be nonnegative")
    try:
        envelope = decode_envelope(data)
        reader = TerseReader(envelope.payload)
        deleted = reader.read_bool()
        file_attributes = reader.read_uleb128(32)
        size = reader.read_uleb128(64)
        creation_delta = reader.read_signed(64)
        access_delta = reader.read_signed(64)
        write_delta = reader.read_signed(64)
        extent_count = reader.read_uleb128(32)
        if extent_count > max_extents:
            raise ArxDecodeError(
                f"file extent count {extent_count} exceeds limit {max_extents}"
            )
        extents: list[Extent] = []
        total_size = 0
        for index in range(extent_count):
            offset = reader.read_uleb128(64)
            length = reader.read_uleb128(64)
            if length > UINT64_MAX - offset:
                raise ArxDecodeError(f"file extent {index} end overflows uint64")
            if length > UINT64_MAX - total_size:
                raise ArxDecodeError("file extent lengths overflow uint64")
            extents.append(Extent(offset, length))
            total_size += length
        if not reader.finished:
            raise ArxDecodeError(
                f"{reader.remaining} trailing bytes in bucket file record"
            )
    except TerseDecodeError as error:
        raise ArxDecodeError(str(error)) from error


    if total_size != size:
        raise ArxDecodeError(
            f"file size {size} does not match extent total {total_size}"
        )
    return BucketFileRecord(
        name=name,
        name_hash=name_hash,
        syzygy_key=syzygy_key,
        deleted=deleted,
        file_attributes=file_attributes,
        size=size,
        creation_time_delta=creation_delta,
        last_access_time_delta=access_delta,
        last_write_time_delta=write_delta,
        creation_time=_absolute_filetime(
            timestamp_base, creation_delta, "creation_time"
        ),
        last_access_time=_absolute_filetime(
            timestamp_base, access_delta, "last_access_time"
        ),
        last_write_time=_absolute_filetime(
            timestamp_base, write_delta, "last_write_time"
        ),
        extents=tuple(extents),
        terse_checksum=envelope.checksum,
        serialized_size=len(data),
    )


def _decode_bucket_group(
    outer_node: object,
    *,
    syzygy: bool,
    timestamp_base: int | None,
    max_files: int,
    max_extents: int,
    output: list[BucketFileRecord],
    names: set[str],
) -> None:
    if outer_node.value.type_id != 0 or outer_node.value.value is not None:
        raise ArxDecodeError("bucket group root value must be NotSet")
    for group in outer_node.children:
        if group.key.type_id != 10 or not isinstance(group.key.value, int):
            raise ArxDecodeError("bucket hash-group keys must be uint32")
        if group.value.type_id != 0 or group.value.value is not None:
            raise ArxDecodeError("bucket hash-group value must be NotSet")
        name_hash = group.key.value
        for entry in group.children:
            if entry.children:
                raise ArxDecodeError("bucket file entries must not have subtrees")
            if entry.value.type_id != 2 or not isinstance(entry.value.value, bytes):
                raise ArxDecodeError("bucket file values must be vector<uint8>")
            syzygy_key: bytes | None
            if syzygy:
                if entry.key.type_id != 0 or not isinstance(entry.key.value, bytes):
                    raise ArxDecodeError(
                        "compact Syzygy bucket keys must be vector<uint8>"
                    )
                syzygy_key = entry.key.value
                if len(syzygy_key) != 17 or syzygy_key[16] not in _SYZYGY_SUFFIXES:
                    raise ArxDecodeError(
                        "compact Syzygy bucket key must be 16 identifier bytes "
                        "plus kind 0, 1, or 2"
                    )
                name = encode_syzygy_file_name(syzygy_key[:16], syzygy_key[16])
            else:
                if entry.key.type_id != 5 or not isinstance(entry.key.value, str):
                    raise ArxDecodeError("ordinary bucket file keys must be wstring")
                name = entry.key.value
                syzygy_key = None
            if name in names:
                raise ArxDecodeError(f"duplicate bucket file name {name!r}")
            if len(output) >= max_files:
                raise ArxDecodeError(f"bucket file count exceeds limit {max_files}")
            output.append(
                decode_bucket_file_record(
                    entry.value.value,
                    name=name,
                    name_hash=name_hash,
                    syzygy_key=syzygy_key,
                    timestamp_base=timestamp_base,
                    max_extents=max_extents,
                )
            )
            names.add(name)


def decode_bucket_tree(
    tree: KVTree,
    *,
    timestamp_base: int | None = None,
    max_files: int = 1_000_000,
    max_extents: int = 0xFFFF,
) -> ArxBucket:


    if max_files < 0:
        raise ValueError("max_files must be nonnegative")
    roots: dict[int, object] = {}
    for node in tree.children:
        if node.key.type_id != 8 or not isinstance(node.key.value, int):
            raise ArxDecodeError("bucket root keys must be uint8")
        key = node.key.value
        if key not in (0, 1, 2):
            raise ArxDecodeError(f"unknown bucket root key {key}")
        if key in roots:
            raise ArxDecodeError(f"duplicate bucket root key {key}")
        roots[key] = node
    if 0 not in roots:
        raise ArxDecodeError("missing bucket version key 0")
    version_node = roots[0]
    if version_node.children or version_node.value.type_id != 11:
        raise ArxDecodeError("bucket version must be a uint8 leaf")
    version = int(version_node.value.value)
    if version != 0:
        raise ArxDecodeError(f"unsupported bucket version {version}")

    files: list[BucketFileRecord] = []
    names: set[str] = set()
    if 1 in roots:
        _decode_bucket_group(
            roots[1],
            syzygy=False,
            timestamp_base=timestamp_base,
            max_files=max_files,
            max_extents=max_extents,
            output=files,
            names=names,
        )
    if 2 in roots:
        _decode_bucket_group(
            roots[2],
            syzygy=True,
            timestamp_base=timestamp_base,
            max_files=max_files,
            max_extents=max_extents,
            output=files,
            names=names,
        )
    return ArxBucket(
        version=version,
        files=tuple(files),
        decoded_size=tree.decoded_size,
        compressed_size=tree.compressed_size,
    )


def decode_bucket(
    data: bytes,
    *,
    timestamp_base: int | None = None,
    max_files: int = 1_000_000,
    max_extents: int = 0xFFFF,
    max_decoded_size: int = 256 * 1024 * 1024,
) -> ArxBucket:
    try:
        tree = decode_kvtree(
            data,
            max_decoded_size=max_decoded_size,
            max_nodes=max_files * 2 + 0x10000 + 3,
            max_depth=3,
        )
    except KVTreeDecodeError as error:
        raise ArxDecodeError(str(error)) from error
    return decode_bucket_tree(
        tree,
        timestamp_base=timestamp_base,
        max_files=max_files,
        max_extents=max_extents,
    )


def _read_filetime(reader: _RawReader) -> int:
    low = reader.uint(4)
    high = reader.uint(4)
    return low | (high << 32)


def decode_monolithic_file_index_payload(
    payload: bytes,
    *,
    max_files: int = 0xFFFF,
    max_extents: int = 0xFFFF,
    max_name_code_units: int = 1_000_000,
) -> tuple[MonolithicFileRecord, ...]:


    if not 0 <= max_files <= 0xFFFF:
        raise ValueError("max_files must be in the range 0..65535")
    if not 0 <= max_extents <= 0xFFFF:
        raise ValueError("max_extents must be in the range 0..65535")
    reader = _RawReader(payload)
    count = reader.uint(2)
    if count > max_files:
        raise ArxDecodeError(f"file count {count} exceeds limit {max_files}")
    result: list[MonolithicFileRecord] = []
    names: set[str] = set()
    for file_index in range(count):
        name = reader.wstring(max_code_units=max_name_code_units)
        if name in names:
            raise ArxDecodeError(f"duplicate monolithic file name {name!r}")
        extent_count = reader.uint(2)
        if extent_count > max_extents:
            raise ArxDecodeError(
                f"file {file_index} extent count {extent_count} exceeds "
                f"limit {max_extents}"
            )
        extents: list[Extent] = []
        total_size = 0
        for extent_index in range(extent_count):
            offset = reader.uint(8)
            length = reader.uint(8)
            if length > UINT64_MAX - offset:
                raise ArxDecodeError(
                    f"file {file_index} extent {extent_index} end overflows uint64"
                )
            if length > UINT64_MAX - total_size:
                raise ArxDecodeError(f"file {file_index} extent total overflows uint64")
            extents.append(Extent(offset, length))
            total_size += length
        attributes = reader.uint(4)
        creation_time = _read_filetime(reader)
        access_time = _read_filetime(reader)
        write_time = _read_filetime(reader)
        size = reader.uint(8)
        if size != total_size:
            raise ArxDecodeError(
                f"file {file_index} size {size} does not match extent total "
                f"{total_size}"
            )
        result.append(
            MonolithicFileRecord(
                name=name,
                extents=tuple(extents),
                file_attributes=attributes,
                creation_time=creation_time,
                last_access_time=access_time,
                last_write_time=write_time,
                size=size,
            )
        )
        names.add(name)
    if not reader.finished:
        raise ArxDecodeError(
            f"{reader.remaining} trailing bytes in monolithic file index payload"
        )
    return tuple(result)


def decode_monolithic_file_index(
    data: bytes,
    *,
    max_files: int = 0xFFFF,
    max_extents: int = 0xFFFF,
    max_name_code_units: int = 1_000_000,
    max_decoded_size: int = 256 * 1024 * 1024,
) -> ArxMonolithicFileIndex:
    payload = _decompress_storage_frame(data, max_decoded_size=max_decoded_size)
    files = decode_monolithic_file_index_payload(
        payload,
        max_files=max_files,
        max_extents=max_extents,
        max_name_code_units=max_name_code_units,
    )
    return ArxMonolithicFileIndex(files, len(payload), len(data))


def _validate_allocator_extents(
    name: str,
    extents: tuple[Extent, ...],
    physical_volume_size: int,
    *,
    minimum_offset: int | None = None,
) -> None:
    for index, extent in enumerate(extents):
        if minimum_offset is not None and extent.offset < minimum_offset:
            raise ArxDecodeError(
                f"{name} extent {index} starts below minimum allocatable "
                f"byte offset 0x{minimum_offset:x}"
            )
        if extent.offset > physical_volume_size:
            raise ArxDecodeError(
                f"{name} extent {index} starts beyond physical volume size"
            )
        if extent.length > physical_volume_size:
            raise ArxDecodeError(
                f"{name} extent {index} length exceeds physical volume size"
            )
        if extent.offset + extent.length > physical_volume_size:
            raise ArxDecodeError(
                f"{name} extent {index} ends beyond physical volume size"
            )


def _validate_allocator_tree_extent(
    extent: Extent,
    *,
    minimum_offset: int,
    physical_volume_size: int,
    context: str,
) -> None:


    if extent.length != ARX_BLOCK_SIZE:
        raise ArxDecodeError(f"{context} length is not exactly 0x1000 bytes")
    if extent.offset & (ARX_BLOCK_SIZE - 1):
        raise ArxDecodeError(f"{context} offset is not 4096-aligned")
    if extent.offset < minimum_offset:
        raise ArxDecodeError(
            f"{context} starts below minimum byte offset 0x{minimum_offset:x}"
        )
    if physical_volume_size < ARX_BLOCK_SIZE:
        raise ArxDecodeError("allocator physical volume is smaller than 4096 bytes")
    if extent.offset > physical_volume_size - ARX_BLOCK_SIZE:
        raise ArxDecodeError(f"{context} exceeds allocator physical volume size")


def _verify_nextgen_allocator_state(
    state: ArxNextGenAllocatorState,
    *,
    captured_volume_size: int,
) -> None:


    if state.physical_volume_size > captured_volume_size:
        raise ArxDecodeError(
            "allocator physical volume size exceeds the captured volume"
        )
    if state.minimum_allocatable_offset > state.physical_volume_size:
        raise ArxDecodeError(
            "allocator minimum byte offset exceeds physical volume size"
        )
    if state.minimum_allocatable_offset < ARX_SUPERBLOCK_ROOT_LENGTH:
        raise ArxDecodeError("allocator reserved byte size is below 0x2000")
    if state.indirection_depth > 0x10:
        raise ArxDecodeError("allocator indirection depth exceeds 16")
    _validate_allocator_extents(
        "free-list", state.free_list, state.physical_volume_size
    )
    _validate_allocator_extents(
        "frozen-list", state.frozen_list, state.physical_volume_size
    )
    for index, extent in enumerate(state.root_leaf_pointers):
        _validate_allocator_tree_extent(
            extent,
            minimum_offset=state.minimum_allocatable_offset,
            physical_volume_size=state.physical_volume_size,
            context=f"root tree pointer {index}",
        )


def decode_nextgen_allocator_payload(
    payload: bytes,
    *,
    max_extents: int = 1_000_000,
    max_vector_size: int = 256 * 1024 * 1024,
) -> ArxNextGenAllocatorState:


    reader = _RawReader(payload)
    version = reader.uint(8)
    if version != 1:
        raise ArxDecodeError(f"unsupported next-gen allocator version {version}")
    generation = reader.uint(8)
    pinned_generation = reader.uint(8)
    pinned_root = Extent(reader.uint(8), reader.uint(8))
    physical_volume_size = reader.uint(8)
    freeze_value = reader.uint(1)
    if freeze_value not in (0, 1):
        raise ArxDecodeError(f"invalid allocator freeze flag {freeze_value}")
    minimum_offset = reader.uint(8)

    free_list = decode_block_runs(
        reader.vector(max_size=max_vector_size), max_extents=max_extents
    )
    indirection_depth = reader.uint(8)
    root_pointers = decode_leaf_pointers(
        reader.vector(max_size=max_vector_size), max_extents=max_extents
    )
    frozen_list = decode_block_runs(
        reader.vector(max_size=max_vector_size), max_extents=max_extents
    )
    if not reader.finished:
        raise ArxDecodeError(
            f"{reader.remaining} trailing bytes in next-gen allocator payload"
        )
    return ArxNextGenAllocatorState(
        version=version,
        generation=generation,
        pinned_file_index_generation=pinned_generation,
        pinned_file_index_root=pinned_root,
        physical_volume_size=physical_volume_size,
        freeze_active=bool(freeze_value),
        minimum_allocatable_offset=minimum_offset,
        free_list=free_list,
        indirection_depth=indirection_depth,
        root_leaf_pointers=root_pointers,
        frozen_list=frozen_list,
        decoded_size=len(payload),
        compressed_size=0,
    )


def decode_nextgen_allocator(
    data: bytes,
    *,
    max_extents: int = 1_000_000,
    max_vector_size: int = 256 * 1024 * 1024,
    max_decoded_size: int = 256 * 1024 * 1024,
) -> ArxNextGenAllocatorState:
    payload = _decompress_storage_frame(data, max_decoded_size=max_decoded_size)
    state = decode_nextgen_allocator_payload(
        payload,
        max_extents=max_extents,
        max_vector_size=max_vector_size,
    )
    return replace(state, compressed_size=len(data))


def _slice_physical_extent(data: bytes, extent: Extent, *, name: str) -> bytes:
    if extent.length == 0:
        raise ArxDecodeError(f"{name} has zero byte length")
    end = extent.offset + extent.length
    if end > len(data):
        raise ArxDecodeError(
            f"{name} byte range 0x{extent.offset:x}..0x{end:x} exceeds "
            f"the {len(data)}-byte physical volume capture"
        )
    return data[extent.offset:end]


def decode_nextgen_allocator_zigzag(
    data: bytes,
    extent: Extent,
    *,
    max_extents: int = 1_000_000,
    max_decoded_size: int = 256 * 1024 * 1024,
) -> ArxNextGenAllocatorRoot:


    raw = _slice_physical_extent(data, extent, name="allocator root")
    if len(raw) & (ARX_BLOCK_SIZE - 1):
        raise ArxDecodeError("allocator root byte length is not 4096-aligned")
    half_size = len(raw) >> 1
    halves: list[ArxNextGenAllocatorHalf] = []
    for slot in range(2):
        offset = extent.offset + slot * half_size
        raw_half = raw[slot * half_size : (slot + 1) * half_size]
        serialized_size = 0
        try:
            encoded = _extract_storage_frame_prefix(
                raw_half,
                max_decoded_size=max_decoded_size,
                context=f"allocator slot {slot}",
            )
            serialized_size = len(encoded)
            state = decode_nextgen_allocator(
                encoded,
                max_extents=max_extents,
                max_decoded_size=max_decoded_size,
            )
            halves.append(
                ArxNextGenAllocatorHalf(slot, offset, serialized_size, state, None)
            )
        except ArxDecodeError as error:
            halves.append(
                ArxNextGenAllocatorHalf(slot, offset, serialized_size, None, str(error))
            )

    valid = [half for half in halves if half.state is not None]
    if not valid:
        details = "; ".join(
            f"slot {half.slot}: {half.error}" for half in halves
        )
        raise ArxDecodeError(f"neither next-gen allocator generation is valid ({details})")
    selected = max(valid, key=lambda half: (half.state.generation, half.slot))
    assert selected.state is not None
    _verify_nextgen_allocator_state(
        selected.state,
        captured_volume_size=len(data),
    )






    current = selected.state.root_leaf_pointers
    tree_blocks: list[Extent] = []
    spilled_free: list[Extent] = []
    seen: set[Extent] = set()
    max_tree_blocks = (selected.state.physical_volume_size >> 12) + 1
    for tier in range(selected.state.indirection_depth + 1):
        next_tier: list[Extent] = []
        for pointer_index, pointer in enumerate(current):
            context = f"allocator tree tier {tier} pointer {pointer_index}"
            _validate_allocator_tree_extent(
                pointer,
                minimum_offset=selected.state.minimum_allocatable_offset,
                physical_volume_size=selected.state.physical_volume_size,
                context=context,
            )
            if pointer in seen:
                raise ArxDecodeError(f"{context} repeats an earlier tree block")
            seen.add(pointer)
            tree_blocks.append(pointer)
            if len(tree_blocks) > max_tree_blocks:
                raise ArxDecodeError(
                    "allocator tree has more blocks than the volume can hold"
                )
            raw_block = _slice_physical_extent(data, pointer, name=context)
            if tier < selected.state.indirection_depth:
                decoded = decode_leaf_pointer_block(
                    raw_block,
                    max_extents=max_extents,
                )
                next_tier.extend(decoded.extents)
                if len(next_tier) > max_extents:
                    raise ArxDecodeError(
                        "allocator pointer tier exceeds the configured extent limit"
                    )
            else:
                decoded = decode_block_run_block(
                    raw_block,
                    max_extents=max_extents,
                )
                _validate_allocator_extents(
                    "leaf free-run",
                    decoded.extents,
                    selected.state.physical_volume_size,
                    minimum_offset=selected.state.minimum_allocatable_offset,
                )
                spilled_free.extend(decoded.extents)
                if len(spilled_free) > max_extents:
                    raise ArxDecodeError(
                        "allocator spilled free list exceeds the configured extent limit"
                    )
        current = tuple(next_tier)

    return ArxNextGenAllocatorRoot(
        extent,
        (halves[0], halves[1]),
        selected.slot,
        selected.state,
        tuple(tree_blocks),
        tuple(spilled_free),
    )


def decode_hash_directory_zigzag(
    data: bytes,
    extent: Extent,
    *,
    max_decoded_size: int = 256 * 1024 * 1024,
) -> tuple[
    tuple[ArxHashDirectoryHalf, ArxHashDirectoryHalf],
    int,
    ArxHashDirectory,
]:


    raw = _slice_physical_extent(data, extent, name="HashDirectory root")
    if len(raw) & (ARX_BLOCK_SIZE - 1):
        raise ArxDecodeError("HashDirectory root byte length is not 4096-aligned")
    half_size = len(raw) >> 1
    halves: list[ArxHashDirectoryHalf] = []
    for slot in range(2):
        offset = extent.offset + slot * half_size
        raw_half = raw[slot * half_size : (slot + 1) * half_size]
        serialized_size = 0
        try:
            encoded = _extract_kvtree_from_zigzag_half(
                raw_half,
                max_decoded_size=max_decoded_size,
                context=f"HashDirectory slot {slot}",
            )
            serialized_size = len(encoded)
            directory = decode_hash_directory(
                encoded,
                volume_size=len(data),
                max_decoded_size=max_decoded_size,
            )
            halves.append(
                ArxHashDirectoryHalf(
                    slot, offset, serialized_size, directory, None
                )
            )
        except ArxDecodeError as error:
            halves.append(
                ArxHashDirectoryHalf(slot, offset, serialized_size, None, str(error))
            )

    valid = [half for half in halves if half.directory is not None]
    if not valid:
        details = "; ".join(
            f"slot {half.slot}: {half.error}" for half in halves
        )
        raise ArxDecodeError(f"neither HashDirectory generation is valid ({details})")
    selected = max(valid, key=lambda half: (half.directory.generation, half.slot))
    assert selected.directory is not None
    return (halves[0], halves[1]), selected.slot, selected.directory


def decode_extendible_file_index(
    data: bytes,
    extent: Extent,
    *,
    timestamp_base: int | None = None,
    max_files: int = 1_000_000,
    max_extents: int = 0xFFFF,
    max_decoded_size: int = 256 * 1024 * 1024,
) -> ArxExtendibleFileIndexSnapshot:


    halves, selected_slot, directory = decode_hash_directory_zigzag(
        data,
        extent,
        max_decoded_size=max_decoded_size,
    )
    extent_slots: dict[Extent, list[int]] = {}
    for entry in directory.entries:
        extent_slots.setdefault(entry.extent, []).append(entry.slot)

    buckets: list[ArxBucketSnapshot] = []
    for bucket_extent, slots in sorted(
        extent_slots.items(), key=lambda item: (item[0].offset, item[0].length)
    ):
        raw = _slice_physical_extent(data, bucket_extent, name="Bucket")
        encoded = _extract_kvtree_from_zigzag_half(
            raw,
            max_decoded_size=max_decoded_size,
            context=f"Bucket at 0x{bucket_extent.offset:x}",
        )
        bucket = decode_bucket(
            encoded,
            timestamp_base=timestamp_base,
            max_files=max_files,
            max_extents=max_extents,
            max_decoded_size=max_decoded_size,
        )
        buckets.append(
            ArxBucketSnapshot(
                bucket_extent,
                tuple(slots),
                len(encoded),
                bucket,
            )
        )
    return ArxExtendibleFileIndexSnapshot(
        extent,
        halves,
        selected_slot,
        directory,
        tuple(buckets),
    )


def scan_reserved_allocator_halves(
    data: bytes,
    superblock: ArxSuperblock,
    *,
    max_extents: int = 1_000_000,
    max_decoded_size: int = 256 * 1024 * 1024,
) -> ArxNextGenAllocatorRoot:


    found: list[tuple[int, int, ArxNextGenAllocatorState]] = []
    reserved = max(superblock.reserved_block_count, 2)
    for block in range(2, min(reserved, len(data) // ARX_BLOCK_SIZE)):
        offset = block * ARX_BLOCK_SIZE
        raw = data[offset : offset + ARX_BLOCK_SIZE]
        if raw[:4] != b"\x04\x22\x4d\x18":
            continue
        try:
            encoded = _extract_storage_frame_prefix(raw, max_decoded_size=max_decoded_size, context=f"reserved block {block}")
            state = decode_nextgen_allocator(encoded, max_extents=max_extents, max_decoded_size=max_decoded_size)
        except ArxDecodeError:
            continue
        found.append((block, len(encoded), state))
    if not found:
        raise ArxDecodeError("no next-gen allocator state in the reserved blocks")
    found = found[:2]
    halves = [
        ArxNextGenAllocatorHalf(slot, block * ARX_BLOCK_SIZE, size, state, None)
        for slot, (block, size, state) in enumerate(found)
    ]
    if len(halves) == 1:
        halves.append(ArxNextGenAllocatorHalf(1, halves[0].offset, 0, None, "only one allocator state was found"))
    first = found[0][0]
    span = (2 * (found[1][0] - first) if len(found) > 1 else 1) * ARX_BLOCK_SIZE
    selected = max((half for half in halves if half.state is not None), key=lambda half: (half.state.generation, half.slot))
    assert selected.state is not None
    _verify_nextgen_allocator_state(selected.state, captured_volume_size=len(data))
    return ArxNextGenAllocatorRoot(
        Extent(first * ARX_BLOCK_SIZE, span), (halves[0], halves[1]), selected.slot, selected.state, (), ()
    )


def decode_physical_volume(
    data: bytes,
    *,
    timestamp_base: int | None = None,
    max_files: int = 1_000_000,
    max_extents: int = 1_000_000,
    max_decoded_size: int = 256 * 1024 * 1024,
) -> ArxPhysicalVolume:


    superblocks = decode_physical_volume_superblocks(
        data,
        max_decoded_size=max_decoded_size,
    )
    try:
        allocator = decode_nextgen_allocator_zigzag(
            data,
            superblocks.selected.allocator_root_block,
            max_extents=max_extents,
            max_decoded_size=max_decoded_size,
        )
    except ArxDecodeError:



        try:
            allocator = decode_nextgen_allocator_zigzag(
                data,
                ZIGZAG_ALLOCATOR_ROOT,
                max_extents=max_extents,
                max_decoded_size=max_decoded_size,
            )
        except ArxDecodeError:
            allocator = scan_reserved_allocator_halves(
                data,
                superblocks.selected,
                max_extents=max_extents,
                max_decoded_size=max_decoded_size,
            )
    if timestamp_base is None:

        timestamp_base = superblocks.selected.creation_time
    file_index_root = allocator.selected.pinned_file_index_root
    raw_file_index = _slice_physical_extent(
        data, file_index_root, name="pinned FileIndex root"
    )

    try:
        encoded = _extract_storage_frame_prefix(
            raw_file_index,
            max_decoded_size=max_decoded_size,
            context="monolithic FileIndex root",
        )
        monolithic = decode_monolithic_file_index(
            encoded,
            max_files=min(max_files, 0xFFFF),
            max_extents=min(max_extents, 0xFFFF),
            max_decoded_size=max_decoded_size,
        )
        return ArxPhysicalVolume(
            superblocks,
            allocator,
            file_index_root,
            "monolithic",
            monolithic,
            None,
        )
    except ArxDecodeError as monolithic_error:
        try:
            extendible = decode_extendible_file_index(
                data,
                file_index_root,
                timestamp_base=timestamp_base,
                max_files=max_files,
                max_extents=min(max_extents, 0xFFFF),
                max_decoded_size=max_decoded_size,
            )
        except ArxDecodeError as extendible_error:
            raise ArxDecodeError(
                "pinned FileIndex root is neither a valid monolithic nor "
                "extendible index: monolithic: "
                f"{monolithic_error}; extendible: {extendible_error}"
            ) from extendible_error
        return ArxPhysicalVolume(
            superblocks,
            allocator,
            file_index_root,
            "extendible",
            None,
            extendible,
        )


@dataclass(frozen=True)
class ArxExtractedFile:


    name: str
    data: bytes
    size: int
    extents: tuple[Extent, ...]
    last_write_time: int | None
    stale: bool = False

    def to_json_dict(self) -> dict[str, object]:
        return {"name": self.name, "size": self.size, "extents": [asdict(extent) for extent in self.extents],
                "last_write_time": self.last_write_time, "stale": self.stale}


def stale_bucket_records(
    data: bytes,
    live_names: set[str],
    current_offsets: set[int],
    *,
    timestamp_base: int | None = None,
    max_files: int = 1_000_000,
    max_decoded_size: int = 16 * 1024 * 1024,
) -> tuple[list[BucketFileRecord], int]:


    found: dict[str, BucketFileRecord] = {}
    copies = 0
    for offset in range(0, len(data) - ARX_BLOCK_SIZE + 1, ARX_BLOCK_SIZE):
        if offset in current_offsets:
            continue
        try:
            raw = _slice_physical_extent(data, Extent(offset, ARX_BLOCK_SIZE), name="Bucket")
            encoded = _extract_kvtree_from_zigzag_half(raw, max_decoded_size=max_decoded_size, context="stale Bucket")
            bucket = decode_bucket(encoded, timestamp_base=timestamp_base, max_files=max_files,
                                   max_decoded_size=max_decoded_size)
        except (ArxDecodeError, ValueError):
            continue
        copies += 1
        for record in bucket.files:
            if record.deleted or record.name in live_names:
                continue
            earlier = found.get(record.name)
            if earlier is None or record.last_write_time_delta > earlier.last_write_time_delta:
                found[record.name] = record
    return sorted(found.values(), key=lambda record: record.name), copies


def extract_volume_files(
    data: bytes,
    *,
    max_files: int = 1_000_000,
    max_decoded_size: int = 256 * 1024 * 1024,
    include_stale: bool = False,
) -> tuple[list[ArxExtractedFile], dict[str, object]]:


    volume = decode_physical_volume(data, max_files=max_files, max_decoded_size=max_decoded_size)
    summary: dict[str, object] = {
        "volume_size": len(data),
        "superblock_slot": volume.superblocks.selected_slot if hasattr(volume.superblocks, "selected_slot") else None,
        "allocator_extent": asdict(volume.allocator.extent),
        "allocator_generation": volume.allocator.selected.generation,
        "file_index_root": asdict(volume.file_index_root),
        "file_index_kind": volume.file_index_kind,
        "skipped": [],
    }
    records: list[object] = []
    if volume.monolithic_file_index is not None:
        records = list(volume.monolithic_file_index.files)
    elif volume.extendible_file_index is not None:
        summary["file_index_generation"] = volume.extendible_file_index.selected.generation
        for snapshot in volume.extendible_file_index.buckets:
            records.extend(record for record in snapshot.bucket.files if not record.deleted)
    files: list[ArxExtractedFile] = []
    skipped: list[dict[str, object]] = summary["skipped"]
    for record in records:
        extents = tuple(record.extents)
        if any(extent.offset + extent.length > len(data) for extent in extents):
            skipped.append({"name": record.name, "reason": "an extent runs past the volume"})
            continue
        raw = b"".join(data[extent.offset : extent.offset + extent.length] for extent in extents)
        if len(raw) < record.size:
            skipped.append({"name": record.name, "reason": f"extents hold {len(raw)} of {record.size} bytes"})
            continue
        files.append(ArxExtractedFile(record.name, raw[: record.size], record.size, extents, record.last_write_time))
    summary["files"] = len(files)
    if include_stale and volume.extendible_file_index is not None:
        live_names = {item.name for item in files}
        current = {snapshot.extent.offset for snapshot in volume.extendible_file_index.buckets}
        stale, copies = stale_bucket_records(data, live_names, current, max_files=max_files,
                                             timestamp_base=volume.superblocks.selected.creation_time)
        added = 0
        for record in stale:
            extents = tuple(record.extents)
            if any(extent.offset + extent.length > len(data) for extent in extents):
                skipped.append({"name": record.name, "reason": "stale: an extent runs past the volume"})
                continue
            raw = b"".join(data[extent.offset : extent.offset + extent.length] for extent in extents)
            if len(raw) < record.size:
                skipped.append({"name": record.name, "reason": f"stale: extents hold {len(raw)} of {record.size} bytes"})
                continue
            files.append(ArxExtractedFile(record.name, raw[: record.size], record.size, extents,
                                          record.last_write_time, stale=True))
            added += 1
        summary["stale_bucket_copies"] = copies
        summary["stale_files"] = added
    return files, summary


def _extents_json(extents: tuple[Extent, ...]) -> dict[str, object]:
    return {
        "extent_count": len(extents),
        "extents": [asdict(extent) for extent in extents],
    }


def _main() -> int:
    parser = argparse.ArgumentParser(description="decode recovered Office Arx primitives")
    parser.add_argument(
        "kind",
        choices=(
            "block-runs",
            "leaf-pointers",
            "block-run-block",
            "leaf-pointer-block",
            "superblock",
            "volume-superblocks",
            "physical-volume",
            "hash-directory",
            "bucket",
            "file-index",
            "allocator",
        ),
    )
    parser.add_argument("path", type=Path)
    parser.add_argument("--max-extents", type=int, default=1_000_000)
    parser.add_argument("--max-files", type=int, default=1_000_000)
    parser.add_argument("--volume-size", type=int)
    parser.add_argument("--timestamp-base", type=int)
    args = parser.parse_args()
    try:
        data = args.path.read_bytes()
        if args.kind == "block-runs":
            result = _extents_json(
                decode_block_runs(data, max_extents=args.max_extents)
            )
        elif args.kind == "leaf-pointers":
            result = _extents_json(
                decode_leaf_pointers(data, max_extents=args.max_extents)
            )
        elif args.kind == "block-run-block":
            result = decode_block_run_block(
                data, max_extents=args.max_extents
            ).to_json_dict()
        elif args.kind == "leaf-pointer-block":
            result = decode_leaf_pointer_block(
                data, max_extents=args.max_extents
            ).to_json_dict()
        elif args.kind == "superblock":
            result = decode_superblock(data, volume_size=args.volume_size).to_json_dict()
        elif args.kind == "volume-superblocks":
            result = decode_physical_volume_superblocks(
                data, volume_size=args.volume_size
            ).to_json_dict()
        elif args.kind == "physical-volume":
            result = decode_physical_volume(
                data,
                timestamp_base=args.timestamp_base,
                max_files=args.max_files,
                max_extents=args.max_extents,
            ).to_json_dict()
        elif args.kind == "hash-directory":
            result = decode_hash_directory(
                data, volume_size=args.volume_size
            ).to_json_dict()
        elif args.kind == "bucket":
            result = decode_bucket(
                data,
                timestamp_base=args.timestamp_base,
                max_files=args.max_files,
                max_extents=min(args.max_extents, 0xFFFF),
            ).to_json_dict()
        elif args.kind == "file-index":
            result = decode_monolithic_file_index(
                data,
                max_files=min(args.max_files, 0xFFFF),
                max_extents=min(args.max_extents, 0xFFFF),
            ).to_json_dict()
        else:
            result = decode_nextgen_allocator(
                data, max_extents=args.max_extents
            ).to_json_dict()
        print(json.dumps(result, indent=2))
    except (OSError, ArxDecodeError, ValueError) as error:
        parser.error(str(error))
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
