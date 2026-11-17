

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..crypto.spookyhash import cluster_id_from_label
from ..formats.terse_codec import (
    TerseDecodeError,
    TerseReader,
    decode_document_metadata,
    decode_envelope,
)

RECORD_MARKER = 0x75
DEFAULT_CLUSTER_SIZE = 0x1000


KNOWN_LABELS = (
    "_boot",
    "_vault",
    "_arxvol",
    "DocumentMetadata",
    "DocumentStorageRevisions",
    "DocumentList",
    "AuditLog",
)
LABEL_BY_ID = {cluster_id_from_label(label): label for label in KNOWN_LABELS}
BOOT_CLUSTER_SET_FILE_NAME = f"{cluster_id_from_label('_boot')}.C4"


class ClusterSetDecodeError(ValueError):
    pass


@dataclass(frozen=True)
class ClusterRecord:
    offset: int
    cluster_count: int
    cluster_id: int
    generation: int
    value: bytes

    @property
    def label(self) -> str | None:
        return LABEL_BY_ID.get(self.cluster_id)


@dataclass
class ClusterSetScan:
    size: int
    cluster_size: int
    records: list[ClusterRecord] = field(default_factory=list)
    empty_clusters: list[int] = field(default_factory=list)
    damaged_clusters: list[tuple[int, str]] = field(default_factory=list)

    def generations(self, cluster_id: int) -> list[ClusterRecord]:
        return sorted(
            (record for record in self.records if record.cluster_id == cluster_id),
            key=lambda record: record.generation,
        )

    def current(self, cluster_id: int) -> ClusterRecord | None:
        records = self.generations(cluster_id)
        return records[-1] if records else None

    def by_label(self, label: str) -> ClusterRecord | None:
        return self.current(cluster_id_from_label(label))

    def to_json_dict(self) -> dict[str, Any]:
        ids = sorted({record.cluster_id for record in self.records})
        return {
            "size": self.size,
            "cluster_size": self.cluster_size,
            "empty_clusters": self.empty_clusters,
            "damaged_clusters": [
                {"offset": offset, "reason": reason} for offset, reason in self.damaged_clusters
            ],
            "properties": [
                {
                    "cluster_id": f"0x{cluster_id:016x}",
                    "label": LABEL_BY_ID.get(cluster_id),
                    "generations": [
                        {
                            "generation": record.generation,
                            "offset": record.offset,
                            "clusters": record.cluster_count,
                            "value_size": len(record.value),
                        }
                        for record in self.generations(cluster_id)
                    ],
                }
                for cluster_id in ids
            ],
        }


def parse_cluster_record(data: bytes, offset: int, cluster_size: int) -> ClusterRecord:
    if data[offset] != RECORD_MARKER:
        raise ClusterSetDecodeError(f"missing 0x75 record marker at 0x{offset:x}")
    try:
        envelope = decode_envelope(data[offset + 1 :], allow_trailing=True)
        reader = TerseReader(envelope.payload)
        cluster_id = reader.read_uleb128(64)
        generation = reader.read_uleb128(64)
        value = reader.read_byte_vector()
    except TerseDecodeError as error:
        raise ClusterSetDecodeError(f"invalid cluster record at 0x{offset:x}: {error}") from error
    if not reader.finished:
        raise ClusterSetDecodeError(f"cluster record at 0x{offset:x} has trailing payload bytes")
    used = 1 + 9 + envelope.payload_size
    cluster_count = -(-used // cluster_size)
    padding = data[offset + used : offset + cluster_count * cluster_size]
    if any(padding):
        raise ClusterSetDecodeError(f"cluster record at 0x{offset:x} has nonzero padding")
    return ClusterRecord(offset, cluster_count, cluster_id, generation, value)


def scan_cluster_set(data: bytes, cluster_size: int = DEFAULT_CLUSTER_SIZE) -> ClusterSetScan:


    scan = ClusterSetScan(size=len(data), cluster_size=cluster_size)
    offset = 0
    while offset < len(data):
        cluster = data[offset : offset + cluster_size]
        if not any(cluster):
            scan.empty_clusters.append(offset)
            offset += cluster_size
            continue
        try:
            record = parse_cluster_record(data, offset, cluster_size)
        except ClusterSetDecodeError as error:
            scan.damaged_clusters.append((offset, str(error)))
            offset += cluster_size
            continue
        scan.records.append(record)
        offset += record.cluster_count * cluster_size
    return scan







@dataclass
class DocumentView:
    document_id: bytes
    identifiers: dict[int, bytes]
    metadata: dict[int, tuple[int, Any]]
    trailer: tuple[int, int, int]


def decode_document_list(value: bytes) -> tuple[int, list[DocumentView]]:


    envelope = decode_envelope(value)
    reader = TerseReader(envelope.payload)
    version = reader.read_uleb128(16)
    count = reader.read_uleb128(16)
    documents = []
    for _ in range(count):
        document_id = reader.read_byte_vector()
        identifiers = {}
        for _ in range(reader.read_uleb128(16)):
            key = reader.read_uleb128(64)
            identifiers[key] = reader.read_byte_vector()
        metadata = {}
        for _ in range(reader.read_uleb128(16)):
            key = reader.read_uleb128(64)
            type_id = reader.read_uleb128(64) if version >= 6 else None
            metadata[key] = (type_id, _read_typed(reader, type_id))
        trailer = (reader.read_uleb128(64), reader.read_uleb128(64), reader.read_uleb128(64))
        documents.append(DocumentView(document_id, identifiers, metadata, trailer))
    if not reader.finished:
        raise ClusterSetDecodeError("DocumentList has trailing bytes")
    return version, documents


def _read_typed(reader: TerseReader, type_id: int | None) -> Any:
    if type_id == 1:
        return bool(reader.read_exact(1)[0])
    if type_id == 2:
        return reader.read_byte_vector()
    if type_id == 3:
        return reader.read_guid()["guid"]
    if type_id == 4:
        return reader.read_uleb128(16)
    if type_id == 5:
        return reader.read_uleb128(32)
    if type_id == 6:
        return reader.read_uleb128(64)
    if type_id == 7:
        return reader.read_wstring()
    raise ClusterSetDecodeError(f"unsupported DocumentList value type {type_id}")


def main() -> int:
    parser = argparse.ArgumentParser(description="scan a Syzygy .C4 cluster-set file")
    parser.add_argument("path", type=Path)
    args = parser.parse_args()
    data = args.path.read_bytes()
    scan = scan_cluster_set(data)
    result = scan.to_json_dict()
    metadata = scan.by_label("DocumentMetadata")
    if metadata is not None:
        decoded = decode_document_metadata(metadata.value)
        result["document_metadata_element_count"] = len(decoded.elements)
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
