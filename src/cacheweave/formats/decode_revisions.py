

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .decode_kvtree import KVNode, KVTreeDecodeError, decode_kvtree
from .terse_codec import (
    TerseDecodeError,
    decode_last_ocs_save,
    decode_revision_clock_data,
)


class RevisionsDecodeError(ValueError):
    pass


@dataclass(frozen=True)
class PropertySchema:
    name: str
    value_type: str
    revision_data_offset: int | None






PROPERTY_SCHEMA: dict[int, PropertySchema] = {
    0x00: PropertySchema("parents", "vector<uint32>", 0x18),
    0x01: PropertySchema("labels", "vector<uint8>", 0x30),
    0x02: PropertySchema("host_known_version_info", "vector<uint8>", 0x48),
    0x03: PropertySchema("remote_revision_id", "vector<uint8>", 0x60),
    0x04: PropertySchema("app_data", "vector<uint8>", 0x78),
    0x05: PropertySchema("dictionary_pile_id", "array<uint8,16>", 0x1A0),
    0x06: PropertySchema("local_save_time", "uint64", 0x90),
    0x07: PropertySchema("revision_clock_data", "vector<uint8>", 0xA0),
    0x08: PropertySchema("probability_vortex", "vector<uint8>", None),
    0x09: PropertySchema("sync_token", "vector<uint8>", 0xB8),
    0x0B: PropertySchema("clock_data", "vector<uint8>", 0xD0),
    0x0C: PropertySchema("zip_parts_pile_id", "array<uint8,16>", 0x1C8),
    0x0D: PropertySchema("single_blob_id", "array<uint8,16>", 0x1F0),
    0x0E: PropertySchema("zip_parts_additional_pile_id", "array<uint8,16>", 0x208),
    0x0F: PropertySchema("cobalt_host_knowledge", "vector<uint8>", 0xE8),
    0x10: PropertySchema("revision_metadata_flags", "vector<uint8>", 0x100),
    0x11: PropertySchema("size_in_bytes", "uint64", 0x118),
    0x12: PropertySchema("quick_xor_hash", "vector<uint8>", 0x120),
    0x13: PropertySchema("is_dirty_from_host", "bool", 0x138),
    0x14: PropertySchema("last_ocs_save", "vector<uint8>", 0x150),
    0x15: PropertySchema("contained_in_remote_revision_id", "vector<uint8>", 0x168),
    0x16: PropertySchema("ocs_revision_format", "string", 0x180),
    0x17: PropertySchema("local_file_last_modified_time", "uint64", 0x140),
}


def _json_value(value: Any) -> Any:
    return value.hex() if isinstance(value, bytes) else value


@dataclass(frozen=True)
class RevisionProperty:
    property_id: int
    name: str
    value_type: str
    value: Any
    revision_data_offset: int | None
    known: bool
    decoded_value: Any | None = None

    def to_json_dict(self) -> dict[str, Any]:
        result = {
            "property_id": f"0x{self.property_id:02x}",
            "name": self.name,
            "value_type": self.value_type,
            "value": _json_value(self.value),
            "known": self.known,
        }
        if self.revision_data_offset is not None:
            result["revision_data_offset"] = f"0x{self.revision_data_offset:x}"
        if self.decoded_value is not None:
            result["decoded_value"] = self.decoded_value
        return result


@dataclass(frozen=True)
class RevisionRecord:
    storage_revision_id: int
    properties: tuple[RevisionProperty, ...]

    def to_json_dict(self) -> dict[str, Any]:
        return {
            "storage_revision_id": self.storage_revision_id,
            "property_count": len(self.properties),
            "properties": [item.to_json_dict() for item in self.properties],
        }


@dataclass(frozen=True)
class DocumentStorageRevisions:
    stream_version: int
    producer_version_packed: int
    producer_build: int
    producer_revision: int
    revisions: tuple[RevisionRecord, ...]
    decoded_size: int
    compressed_size: int
    root_extensions: tuple[dict[str, Any], ...]

    def to_json_dict(self) -> dict[str, Any]:
        return {
            "stream_version": self.stream_version,
            "producer_version_packed": f"0x{self.producer_version_packed:08x}",
            "producer_build": self.producer_build,
            "producer_revision": self.producer_revision,
            "decoded_size": self.decoded_size,
            "compressed_size": self.compressed_size,
            "revision_count": len(self.revisions),
            "revisions": [revision.to_json_dict() for revision in self.revisions],
            "root_extensions": list(self.root_extensions),
        }


def _require_key(node: KVNode, type_name: str, context: str) -> int:
    if node.key.type_name != type_name or not isinstance(node.key.value, int):
        raise RevisionsDecodeError(
            f"{context} key must be {type_name}, got {node.key.type_name}"
        )
    return node.key.value


def _require_leaf(node: KVNode, context: str) -> None:
    if node.children:
        raise RevisionsDecodeError(f"{context} must not have a subtree")


def _unique_nodes(nodes: tuple[KVNode, ...], key_type: str, context: str) -> dict[int, KVNode]:
    result: dict[int, KVNode] = {}
    for node in nodes:
        key = _require_key(node, key_type, context)
        if key in result:
            raise RevisionsDecodeError(f"duplicate {context} key 0x{key:x}")
        result[key] = node
    return result


def _require_value_type(node: KVNode, expected: str, context: str) -> None:
    if node.value.type_name != expected:
        raise RevisionsDecodeError(
            f"{context} must have value type {expected}, got {node.value.type_name}"
        )


_FIXED_BYTE_LENGTHS = {
    0x09: 0x18,
    0x0B: 0x24,
    0x10: 0x08,
}


def _decode_property_value(
    property_id: int, value: Any, *, strict_schema: bool, context: str
) -> Any | None:
    if property_id == 0x07 and isinstance(value, bytes):
        try:
            return decode_revision_clock_data(value).to_json_dict()
        except TerseDecodeError as error:
            if strict_schema:
                raise RevisionsDecodeError(
                    f"{context}: invalid RevisionClockData: {error}"
                ) from error
            return {"decode_error": str(error)}
    expected_size = _FIXED_BYTE_LENGTHS.get(property_id)
    if expected_size is not None and isinstance(value, bytes):
        if strict_schema and len(value) != expected_size:
            raise RevisionsDecodeError(
                f"{context} must be {expected_size} bytes, got {len(value)}"
            )
        return {
            "size": len(value),
            "words_le": [
                int.from_bytes(value[offset : offset + 8], "little")
                for offset in range(0, len(value), 8)
                if len(value[offset : offset + 8]) == 8
            ],
        }
    if property_id == 0x14 and isinstance(value, bytes):
        try:
            return decode_last_ocs_save(value).to_json_dict()
        except TerseDecodeError as error:
            if strict_schema:
                raise RevisionsDecodeError(
                    f"{context}: invalid LastOcsSave: {error}"
                ) from error
            return {"decode_error": str(error)}
    return None


def _decode_revision(node: KVNode, *, strict_schema: bool) -> RevisionRecord:
    revision_id = _require_key(node, "uint32", "revision")
    _require_value_type(node, "NotSet", f"revision {revision_id}")
    properties_by_id = _unique_nodes(
        node.children, "uint16", f"revision {revision_id} property"
    )
    properties: list[RevisionProperty] = []
    for property_id, property_node in sorted(properties_by_id.items()):
        _require_leaf(property_node, f"revision {revision_id} property 0x{property_id:02x}")
        schema = PROPERTY_SCHEMA.get(property_id)
        if schema is None:
            properties.append(
                RevisionProperty(
                    property_id,
                    f"unknown_property_0x{property_id:02x}",
                    property_node.value.type_name,
                    property_node.value.value,
                    None,
                    False,
                    None,
                )
            )
            continue
        if strict_schema:
            _require_value_type(
                property_node,
                schema.value_type,
                f"revision {revision_id} property {schema.name} (0x{property_id:02x})",
            )
        decoded_value = _decode_property_value(
            property_id,
            property_node.value.value,
            strict_schema=strict_schema,
            context=f"revision {revision_id} property {schema.name} (0x{property_id:02x})",
        )
        properties.append(
            RevisionProperty(
                property_id,
                schema.name,
                property_node.value.type_name,
                property_node.value.value,
                schema.revision_data_offset,
                True,
                decoded_value,
            )
        )
    return RevisionRecord(revision_id, tuple(properties))


def decode_document_storage_revisions(
    data: bytes,
    *,
    strict_schema: bool = True,
    max_decoded_size: int = 256 * 1024 * 1024,
    max_nodes: int = 1_000_000,
    max_depth: int = 256,
) -> DocumentStorageRevisions:


    try:
        tree = decode_kvtree(
            data,
            max_decoded_size=max_decoded_size,
            max_nodes=max_nodes,
            max_depth=max_depth,
        )
    except KVTreeDecodeError as error:
        raise RevisionsDecodeError(str(error)) from error

    roots = _unique_nodes(tree.children, "uint16", "root")
    missing = {0, 1, 2} - roots.keys()
    if missing:
        keys = ", ".join(f"0x{key:x}" for key in sorted(missing))
        raise RevisionsDecodeError(f"missing required root key(s): {keys}")

    version_node = roots[0]
    _require_leaf(version_node, "root stream version")
    _require_value_type(version_node, "uint16", "root stream version")

    revisions_node = roots[1]
    _require_value_type(revisions_node, "NotSet", "root revisions node")
    revisions_by_id = _unique_nodes(revisions_node.children, "uint32", "revision")
    revisions = tuple(
        _decode_revision(revisions_by_id[revision_id], strict_schema=strict_schema)
        for revision_id in sorted(revisions_by_id)
    )

    producer_node = roots[2]
    _require_leaf(producer_node, "root producer version")
    _require_value_type(producer_node, "uint32", "root producer version")
    packed = producer_node.value.value

    extensions = tuple(
        node.to_json_dict() for key, node in sorted(roots.items()) if key not in {0, 1, 2}
    )
    return DocumentStorageRevisions(
        stream_version=version_node.value.value,
        producer_version_packed=packed,
        producer_build=packed & 0xFFFF,
        producer_revision=(packed >> 16) & 0xFFFF,
        revisions=revisions,
        decoded_size=tree.decoded_size,
        compressed_size=tree.compressed_size,
        root_extensions=extensions,
    )


def _main() -> int:
    parser = argparse.ArgumentParser(
        description="decode a current Office DocumentStorageRevisions KVTree"
    )
    parser.add_argument("path", type=Path)
    parser.add_argument("--allow-schema-mismatch", action="store_true")
    parser.add_argument("--max-decoded-size", type=int, default=256 * 1024 * 1024)
    parser.add_argument("--max-nodes", type=int, default=1_000_000)
    parser.add_argument("--max-depth", type=int, default=256)
    args = parser.parse_args()
    try:
        decoded = decode_document_storage_revisions(
            args.path.read_bytes(),
            strict_schema=not args.allow_schema_mismatch,
            max_decoded_size=args.max_decoded_size,
            max_nodes=args.max_nodes,
            max_depth=args.max_depth,
        )
        print(json.dumps(decoded.to_json_dict(), indent=2, ensure_ascii=False))
    except (OSError, RevisionsDecodeError) as error:
        parser.error(str(error))
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
