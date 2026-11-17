

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass, field

from .fsshttpb import (
    DE_OBJECT_DATA_BLOB,
    DE_OBJECT_GROUP,
    DE_REVISION_MANIFEST,
    DataElement,
    ExGuid,
    FsshttpbDecodeError,
    ObjectData,
    Reader,
)

FSSHTTPD_SCHEMA_GUID = "0eb93394-571d-41e9-aad3-880d92d31955"
PRIMARY_STREAM_ROOT_GUID = "84defab9-aaa3-4a0d-a3a8-520c77ac7073"

SO_LEAF_NODE = 0x1F
SO_INTERMEDIATE_NODE = 0x20
SO_SIGNATURE = 0x21
SO_DATA_SIZE = 0x22
SO_DATA_HASH = 0x2F


class FsshttpdError(ValueError):
    pass


@dataclass
class NodeHeader:
    kind: str
    signature: bytes
    data_size: int
    data_hash: bytes | None


@dataclass
class ReassemblyReport:
    root: ExGuid
    size: int
    leaf_count: int = 0
    data_node_count: int = 0
    signature_checks: dict[str, int] = field(default_factory=dict)
    missing_objects: list[str] = field(default_factory=list)
    excluded_objects: list[str] = field(default_factory=list)


def parse_node_header(data: bytes) -> NodeHeader | None:


    if len(data) < 4:
        return None
    reader = Reader(data)
    head = reader.peek_header()
    if head.kind != "start16" or not head.compound or head.type not in (
        SO_INTERMEDIATE_NODE,
        SO_LEAF_NODE,
    ):
        return None
    reader.header()
    kind = "intermediate" if head.type == SO_INTERMEDIATE_NODE else "leaf"
    signature_header = reader.header()
    if signature_header.type != SO_SIGNATURE:
        raise FsshttpdError(f"{kind} node lacks a signature (got 0x{signature_header.type:x})")


    signature_end = reader.pos + signature_header.length
    signature = reader.binary_item()
    if reader.pos != signature_end:
        raise FsshttpdError(f"{kind} node signature length mismatch")
    size_header = reader.header()
    if size_header.type != SO_DATA_SIZE or size_header.length != 8:
        raise FsshttpdError(f"{kind} node lacks an 8-byte data size")
    data_size = reader.u64()
    data_hash = None
    nxt = reader.peek_header()
    if nxt.kind.startswith("start") and nxt.type == SO_DATA_HASH:
        reader.header()
        data_hash = reader.take(nxt.length)
    end = reader.header()
    if end.kind not in ("end8", "end16") or end.type != head.type:
        raise FsshttpdError(f"{kind} node end mismatch")
    if reader.remaining:
        raise FsshttpdError(f"{kind} node has {reader.remaining} trailing bytes")
    return NodeHeader(kind, signature, data_size, data_hash)


class ObjectStore:


    def __init__(self, elements: list[DataElement]) -> None:
        self.objects: dict[ExGuid, ObjectData] = {}
        self.blobs: dict[ExGuid, bytes] = {}
        self.groups: dict[ExGuid, DataElement] = {}
        for element in elements:
            if element.type == DE_OBJECT_GROUP:
                self.groups[element.exguid] = element
            elif element.type == DE_OBJECT_DATA_BLOB and element.blob_data is not None:
                self.blobs[element.exguid] = element.blob_data

    def load_groups(self, group_ids: list[ExGuid]) -> list[str]:


        missing = []
        for group_id in group_ids:
            group = self.groups.get(group_id)
            if group is None:
                missing.append(str(group_id))
                continue
            for object_id, (_, data) in group.object_map().items():
                self.objects.setdefault(object_id, data)
        return missing

    def data_of(self, object_id: ExGuid) -> tuple[ObjectData, bytes | None]:
        obj = self.objects.get(object_id)
        if obj is None:
            raise KeyError(object_id)
        if obj.kind == "data":
            return obj, obj.data
        if obj.kind == "blob_reference" and obj.blob_exguid in self.blobs:
            return obj, self.blobs[obj.blob_exguid]
        return obj, None


_LOCAL_FILE_HEADER = b"PK\x03\x04"


def _local_header_length(content: bytes) -> int | None:
    if len(content) < 30 or not content.startswith(_LOCAL_FILE_HEADER):
        return None
    name_len, extra_len = struct.unpack_from("<HH", content, 26)
    return 30 + name_len + extra_len


def _xor_signatures(first: bytes, second: bytes) -> bytes:
    short, long_ = (first, second) if len(first) <= len(second) else (second, first)
    return bytes(a ^ b for a, b in zip(short, long_)) + long_[len(short):]


def classify_zip_chunk_signature(signature: bytes, content: bytes) -> str:


    sha1 = hashlib.sha1(content).digest()
    header_len = _local_header_length(content)
    if header_len is None and len(signature) == 16:

        from ..crypto.md4 import md4

        return "rdc_md4" if md4(content) == signature else "mismatch"
    if header_len is None and len(signature) == 12:
        return "simple_large_unverifiable"
    if header_len is not None:
        if header_len == len(content):
            return "local_header" if signature == sha1 else "mismatch"
        crc, compressed, uncompressed = struct.unpack_from("<III", content, 14)
        header_sig = hashlib.sha1(content[:header_len]).digest()
        data_sig = struct.pack("<IQQ", crc, compressed, uncompressed)
        if header_len + compressed == len(content) and signature in (
            _xor_signatures(header_sig, data_sig),
            header_sig + data_sig,
        ):
            return "combined"
        if signature == sha1:
            return "final"
        return "mismatch"
    if len(signature) == 20:
        crc, compressed, uncompressed = struct.unpack("<IQQ", signature)
        if compressed == len(content):
            return "data"
        if signature == sha1:
            return "final"
        return "mismatch"
    return "unknown"


def _check_signature(node: NodeHeader, content: bytes, report: ReassemblyReport) -> None:
    result = classify_zip_chunk_signature(node.signature, content)
    report.signature_checks[result] = report.signature_checks.get(result, 0) + 1


def reassemble(
    store: ObjectStore,
    root: ExGuid,
    *,
    verify_signatures: bool = True,
) -> tuple[bytes, ReassemblyReport]:


    report = ReassemblyReport(root=root, size=0)

    def visit(object_id: ExGuid, depth: int) -> bytes:
        if depth > 64:
            raise FsshttpdError("node tree is too deep")
        try:
            obj, data = store.data_of(object_id)
        except KeyError:
            report.missing_objects.append(str(object_id))
            raise FsshttpdError(f"object {object_id} is not present") from None
        if data is None:
            report.excluded_objects.append(str(object_id))
            raise FsshttpdError(f"object {object_id} data is excluded or unresolved")
        node = parse_node_header(data)
        if node is None:
            report.data_node_count += 1
            return data
        if node.kind == "leaf":
            report.leaf_count += 1
        content = b"".join(visit(child, depth + 1) for child in obj.object_references)
        if len(content) != node.data_size:
            raise FsshttpdError(
                f"{node.kind} node {object_id} declares {node.data_size} bytes, "
                f"children provide {len(content)}"
            )
        if verify_signatures and node.kind == "leaf":
            _check_signature(node, content, report)
        return content

    payload = visit(root, 0)
    report.size = len(payload)
    return payload, report


def iter_leaf_contents(store: ObjectStore):


    for object_id, obj in store.objects.items():
        data = obj.data if obj.kind == "data" else store.blobs.get(obj.blob_exguid) if obj.kind == "blob_reference" else None
        if data is None:
            continue
        try:
            node = parse_node_header(data)
        except (FsshttpdError, FsshttpbDecodeError):
            continue
        if node is None or node.kind != "leaf":
            continue
        try:
            content, _ = reassemble(store, object_id, verify_signatures=False)
        except (FsshttpdError, FsshttpbDecodeError):
            content = None
        yield object_id, node, content


def _inflate(method: int, data: bytes) -> bytes | None:
    import zlib

    if method == 0:
        return data
    if method == 8:
        try:
            decompressor = zlib.decompressobj(-15)
            out = decompressor.decompress(data) + decompressor.flush()
            return out if decompressor.eof else None
        except zlib.error:
            return None
    return None


def salvage_zip_parts(store: ObjectStore) -> list[dict]:


    import zlib

    headers: list[tuple[ExGuid, bytes, bytes | None, str]] = []
    data_chunks: dict[tuple[int, int, int], list[tuple[ExGuid, bytes]]] = {}
    unresolved = 0
    for object_id, node, content in iter_leaf_contents(store):
        if content is None:
            unresolved += 1
            continue
        kind = classify_zip_chunk_signature(node.signature, content)
        if kind == "local_header":
            headers.append((object_id, content, None, kind))
        elif kind == "combined":
            header_len = _local_header_length(content)
            headers.append((object_id, content[:header_len], content[header_len:], kind))
        elif kind == "data":
            crc, compressed, uncompressed = struct.unpack("<IQQ", node.signature)
            data_chunks.setdefault((crc, compressed, uncompressed), []).append((object_id, content))
    parts: dict[tuple[str, int, int], dict] = {}
    for object_id, header, data, kind in headers:
        (_, _, flags, method, _, _, crc, compressed, uncompressed, name_len, _) = struct.unpack_from(
            "<IHHHHHIIIHH", header
        )
        name = header[30 : 30 + name_len].decode("utf-8" if flags & 0x800 else "cp437", "replace")
        sources = [str(object_id)]
        if data is None:
            candidates = data_chunks.get((crc, compressed, uncompressed), [])
            if not candidates:
                key = (name, crc, uncompressed)
                parts.setdefault(key, {"name": name, "crc32": f"{crc:08x}", "status": "data_chunk_missing",
                                       "chunk_objects": sources})
                continue
            data_id, data = candidates[0]
            sources.append(str(data_id))
        payload = _inflate(method, data)
        verified = payload is not None and len(payload) == uncompressed and (zlib.crc32(payload) & 0xFFFFFFFF) == crc
        key = (name, crc, uncompressed)
        entry = parts.get(key)
        if entry is not None and entry.get("status") == "verified":
            entry["chunk_objects"] = sorted(set(entry["chunk_objects"]) | set(sources))
            continue
        parts[key] = {
            "name": name,
            "crc32": f"{crc:08x}",
            "compressed_size": compressed,
            "size": uncompressed,
            "method": method,
            "chunk_form": "combined" if kind == "combined" else "paired",
            "status": "verified" if verified else "crc_mismatch",
            "chunk_objects": sources,
            "payload": payload if verified else None,
        }
    result = sorted(parts.values(), key=lambda item: (item["name"], item["crc32"]))
    if unresolved:
        result.append({"name": None, "status": "unresolved_leaf_nodes", "count": unresolved})
    return result


def infer_root_objects(store: ObjectStore) -> list[ExGuid]:


    referenced = {child for obj in store.objects.values() for child in obj.object_references}
    roots = []
    for object_id, obj in store.objects.items():
        if object_id in referenced:
            continue
        data = obj.data if obj.kind == "data" else None
        if data is None:
            continue
        try:
            node = parse_node_header(data)
        except (FsshttpdError, FsshttpbDecodeError):
            continue
        if node is not None and node.kind == "intermediate":
            roots.append(object_id)
    return sorted(roots)


def primary_root_object(revision_manifest: DataElement) -> ExGuid:
    if revision_manifest.type != DE_REVISION_MANIFEST:
        raise FsshttpdError("not a revision manifest")
    for root_id, object_id in revision_manifest.revision_roots:
        if root_id.guid == PRIMARY_STREAM_ROOT_GUID:
            return object_id
    raise FsshttpdError("revision manifest has no primary content stream root")
