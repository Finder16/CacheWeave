

from __future__ import annotations

import struct
import uuid
from dataclasses import dataclass, field

from .fsshttpb import FsshttpbDecodeError, Reader, StreamHeader
from .terse_codec import TerseDecodeError, TerseReader, decode_envelope

STORAGE_INDEX_ID = "4b928112-96d9-4d01-a1e8-f6416aae79d6"
STORAGE_MANIFEST_KEY = "{4d9eb530-4da4-4f43-b859-b31cc0700665},1"
CONTEXT_INDEX_ID = "c471fc73-51ab-4739-a380-6160fbe87162"


class BlobHeapDecodeError(ValueError):
    pass


def _exguid(raw: bytes) -> str:
    if len(raw) != 20:
        raise BlobHeapDecodeError("expected 20-byte ExGUID")
    return f"{{{uuid.UUID(bytes_le=raw[:16])}}},{struct.unpack_from('<I', raw, 16)[0]}"


@dataclass(frozen=True)
class BlobAttributes:
    version: int
    sequence: int
    data_element: str


def parse_blob_attributes(raw: bytes) -> BlobAttributes:
    if len(raw) != 29:
        raise BlobHeapDecodeError(f"BlobAttributes must be 29 bytes, got {len(raw)}")
    version, sequence = struct.unpack_from("<BQ", raw, 0)
    if version != 1:
        raise BlobHeapDecodeError(f"unsupported BlobAttributes version {version}")
    return BlobAttributes(version, sequence, _exguid(raw[9:29]))


@dataclass
class IndexEntry:
    key: str
    target: str
    sequence: int


@dataclass
class StorageIndexSnapshot:
    version: int
    indexes: dict[str, list[IndexEntry]] = field(default_factory=dict)

    @property
    def max_sequence(self) -> int:
        return max((e.sequence for entries in self.indexes.values() for e in entries), default=-1)

    def storage_index(self) -> dict[str, object]:


        entries = next((v for k, v in self.indexes.items() if k.startswith(f"{{{STORAGE_INDEX_ID}}}")), [])
        result: dict[str, object] = {"storage_manifest": None, "cells": {}, "revisions": {}}
        for entry in entries:
            if entry.key == STORAGE_MANIFEST_KEY:
                result["storage_manifest"] = entry.target
            elif entry.key.startswith("cell:"):
                result["cells"][entry.key[5:]] = entry.target
            else:
                result["revisions"][entry.key] = entry.target
        return result


def parse_index_entries(blob_plaintext: bytes) -> StorageIndexSnapshot:
    try:
        reader = TerseReader(decode_envelope(blob_plaintext).payload)
        snapshot = StorageIndexSnapshot(reader.read_uleb128(16))
        for _ in range(reader.read_uleb128(32)):
            index_guid = reader.read_guid()["guid"]
            index_value = reader.read_uleb128(32)
            entries = []
            for _ in range(reader.read_uleb128(32)):
                key = reader.read_byte_vector()
                target_guid = reader.read_guid()["guid"]
                target_value = reader.read_uleb128(32)
                sequence = reader.read_uleb128(64)
                if len(key) == 20:
                    key_text = _exguid(key)
                elif len(key) == 40:
                    key_text = f"cell:{_exguid(key[:20])}|{_exguid(key[20:])}"
                else:
                    key_text = f"raw:{key.hex()}"
                entries.append(IndexEntry(key_text, f"{{{target_guid}}},{target_value}", sequence))
            snapshot.indexes[f"{{{index_guid}}},{index_value}"] = entries
        if not reader.finished:
            raise BlobHeapDecodeError("indexEntries has trailing bytes")
    except TerseDecodeError as error:
        raise BlobHeapDecodeError(f"invalid indexEntries record: {error}") from error
    if snapshot.version != 1:
        raise BlobHeapDecodeError(f"unsupported indexEntries version {snapshot.version}")
    return snapshot





HIERARCHY_VERSION = 1
NODE_NULL = 0
NODE_STORAGE_INDEX = 1
NODE_STORAGE_MANIFEST = 2
NODE_CELL_MANIFEST = 3
NODE_REVISION_MANIFEST = 4
NODE_OBJECT_GROUP = 5
NODE_DATA_ELEMENT_FRAGMENT = 6
NODE_OBJECT_DATA_BLOB = 10
NODE_TYPE_NAMES = {
    NODE_NULL: "null",
    NODE_STORAGE_INDEX: "storage_index",
    NODE_STORAGE_MANIFEST: "storage_manifest",
    NODE_CELL_MANIFEST: "cell_manifest",
    NODE_REVISION_MANIFEST: "revision_manifest",
    NODE_OBJECT_GROUP: "object_group",
    NODE_DATA_ELEMENT_FRAGMENT: "data_element_fragment",
    NODE_OBJECT_DATA_BLOB: "object_data_blob",
}
NULL_EXGUID_TEXT = "{00000000-0000-0000-0000-000000000000},0"


@dataclass
class HierarchyNode:
    exguid: str
    serial: str
    size_hint: int
    type: int
    schema_guid: str | None = None
    storage_roots: list[tuple[str, str, str]] = field(default_factory=list)
    current_revision: str | None = None
    revision_id: str | None = None
    base_revision_id: str | None = None
    revision_roots: list[tuple[str, str]] = field(default_factory=list)
    group_flag: bool | None = None
    objects: list[str] = field(default_factory=list)
    object_data_size: int | None = None
    fragment: tuple[str, int, int, int] | None = None
    references: list[str] = field(default_factory=list)
    index_keys: list[str] = field(default_factory=list)

    @property
    def type_name(self) -> str:
        return NODE_TYPE_NAMES.get(self.type, f"unknown_{self.type}")


@dataclass
class HierarchySnapshot:
    version: int
    nodes: list[HierarchyNode] = field(default_factory=list)

    def of_type(self, node_type: int) -> list[HierarchyNode]:
        return [n for n in self.nodes if n.type == node_type]

    def node(self, exguid: str) -> HierarchyNode | None:
        return next((n for n in self.nodes if n.exguid == exguid), None)

    def current_revisions(self) -> set[str]:


        return {n.current_revision for n in self.of_type(NODE_CELL_MANIFEST) if n.current_revision}


def _terse_exguid(reader: TerseReader) -> str:
    guid = uuid.UUID(bytes_le=reader.read_exact(16))
    return f"{{{guid}}},{reader.read_uleb128(32)}"


def _terse_serial(reader: TerseReader) -> str:
    guid = uuid.UUID(bytes_le=reader.read_exact(16))
    return f"{{{guid}}},{reader.read_uleb128(64)}"


def _index_key_text(raw: bytes) -> str:
    if len(raw) == 20:
        return _exguid(raw)
    if len(raw) == 40:
        return f"cell:{_exguid(raw[:20])}|{_exguid(raw[20:])}"
    return f"raw:{raw.hex()}"


def _bounded_count(reader: TerseReader, minimum_item_size: int) -> int:
    count = reader.read_uleb128(64)
    if count * minimum_item_size > reader.remaining:
        raise BlobHeapDecodeError(f"count {count} exceeds the remaining {reader.remaining} bytes")
    return count


def parse_hierarchy_payload(payload: bytes) -> HierarchySnapshot:


    try:
        reader = TerseReader(payload)
        snapshot = HierarchySnapshot(reader.read_exact(1)[0])
        if snapshot.version != HIERARCHY_VERSION:
            raise BlobHeapDecodeError(f"unsupported hierarchy version {snapshot.version}")
        while not reader.finished:
            node = HierarchyNode(
                exguid=_terse_exguid(reader),
                serial=_terse_serial(reader),
                size_hint=reader.read_uleb128(64),
                type=reader.read_uleb128(16),
            )
            if node.type == NODE_STORAGE_MANIFEST:
                node.schema_guid = str(uuid.UUID(bytes_le=reader.read_exact(16)))
                for _ in range(_bounded_count(reader, 51)):
                    node.storage_roots.append((_terse_exguid(reader), _terse_exguid(reader), _terse_exguid(reader)))
            elif node.type == NODE_CELL_MANIFEST:
                node.current_revision = _terse_exguid(reader)
            elif node.type == NODE_REVISION_MANIFEST:
                node.revision_id = _terse_exguid(reader)
                node.base_revision_id = _terse_exguid(reader)
                for _ in range(_bounded_count(reader, 34)):
                    node.revision_roots.append((_terse_exguid(reader), _terse_exguid(reader)))
            elif node.type == NODE_OBJECT_GROUP:
                node.group_flag = reader.read_bool()
                node.objects = [_terse_exguid(reader) for _ in range(_bounded_count(reader, 17))]
                node.object_data_size = reader.read_uleb128(64)
            elif node.type == NODE_DATA_ELEMENT_FRAGMENT:
                node.fragment = (
                    _terse_exguid(reader),
                    reader.read_uleb128(64),
                    reader.read_uleb128(64),
                    reader.read_uleb128(64),
                )
            elif node.type not in (NODE_NULL, NODE_STORAGE_INDEX, NODE_OBJECT_DATA_BLOB):

                raise BlobHeapDecodeError(f"unknown hierarchy node type {node.type}")
            node.references = [_terse_exguid(reader) for _ in range(_bounded_count(reader, 17))]
            node.index_keys = [
                _index_key_text(reader.read_byte_vector()) for _ in range(_bounded_count(reader, 1))
            ]
            snapshot.nodes.append(node)
    except TerseDecodeError as error:
        raise BlobHeapDecodeError(f"invalid hierarchy record: {error}") from error
    return snapshot


def parse_hierarchy_record(blob_plaintext: bytes) -> HierarchySnapshot:


    try:
        envelope = decode_envelope(blob_plaintext)
    except TerseDecodeError as error:
        raise BlobHeapDecodeError(f"invalid hierarchy envelope: {error}") from error
    return parse_hierarchy_payload(envelope.payload)


ROOT_BLOB_SIGNATURE = uuid.UUID("a7cc36af-d5bb-4117-a99e-7b6706b7130d").bytes_le
SO_ROOT_BLOB = 0x12
SO_ROOT_BLOB_KNOWLEDGE_GUID = 0x08
SO_ROOT_BLOB_AGGREGATE_CANT_SUPPLY_KNOWLEDGE = 0x61


@dataclass(frozen=True)
class RootBlob:
    version: int
    compatibility: int
    knowledge_guid: str | None
    aggregate_cant_supply_knowledge: bool
    other_children: tuple[int, ...] = ()


def _skip_stream_object(reader: Reader, header: StreamHeader) -> None:
    if not header.compound:
        reader.take(header.length)
        return
    while True:
        child = reader.header()
        if child.kind in ("end8", "end16"):
            if child.type != header.type:
                raise FsshttpbDecodeError(f"stream object 0x{header.type:x} closed by 0x{child.type:x}")
            return
        _skip_stream_object(reader, child)


def parse_root_blob(blob_plaintext: bytes) -> RootBlob:


    root, end = _parse_root_blob(blob_plaintext)
    if end != len(blob_plaintext):
        raise BlobHeapDecodeError(f"root blob has {len(blob_plaintext) - end} trailing bytes")
    return root


def root_blob_size(data: bytes) -> int:


    return _parse_root_blob(data)[1]


def _parse_root_blob(blob_plaintext: bytes) -> tuple[RootBlob, int]:
    if len(blob_plaintext) < 20 or blob_plaintext[:16] != ROOT_BLOB_SIGNATURE:
        raise BlobHeapDecodeError("not a CSI root blob")
    version, compatibility = struct.unpack_from("<HH", blob_plaintext, 16)
    if version < 1 or compatibility > 3:
        raise BlobHeapDecodeError(f"root blob version {version}/{compatibility} is rejected by ParseRootBlob")
    try:
        reader = Reader(blob_plaintext, 20)
        reader.expect_start(SO_ROOT_BLOB)
        knowledge, aggregate, others = None, False, []
        while True:
            header = reader.header()
            if header.kind in ("end8", "end16"):
                if header.type != SO_ROOT_BLOB:
                    raise BlobHeapDecodeError(f"root blob closed by 0x{header.type:x}")
                break
            if header.type == SO_ROOT_BLOB_KNOWLEDGE_GUID and not header.compound and header.length == 16:
                knowledge = str(uuid.UUID(bytes_le=reader.take(16)))
            elif header.type == SO_ROOT_BLOB_AGGREGATE_CANT_SUPPLY_KNOWLEDGE and not header.compound:
                reader.take(header.length)
                aggregate = True
            else:
                _skip_stream_object(reader, header)
                others.append(header.type)
    except FsshttpbDecodeError as error:
        raise BlobHeapDecodeError(f"invalid root blob: {error}") from error
    if knowledge is None or knowledge == "00000000-0000-0000-0000-000000000000":

        raise BlobHeapDecodeError("root blob has no knowledge GUID")
    return RootBlob(version, compatibility, knowledge, aggregate, tuple(others)), reader.pos


def looks_like_hierarchy_payload(payload: bytes) -> bool:


    if len(payload) < 39 or payload[0] != HIERARCHY_VERSION:
        return False
    try:
        return bool(parse_hierarchy_payload(payload).nodes)
    except BlobHeapDecodeError:
        return False
