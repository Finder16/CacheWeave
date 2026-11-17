


from __future__ import annotations

import argparse
import hashlib
import html
import io
import json
import re
import struct
import sys
import uuid
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .formats.arx_codec import ArxDecodeError, decode_syzygy_identifier, encode_syzygy_identifier, extract_volume_files
from .formats.csi_blobheap import (
    NODE_OBJECT_GROUP,
    NODE_REVISION_MANIFEST,
    NULL_EXGUID_TEXT,
    ROOT_BLOB_SIGNATURE,
    BlobHeapDecodeError,
    HierarchySnapshot,
    looks_like_hierarchy_payload,
    parse_blob_attributes,
    parse_hierarchy_record,
    parse_index_entries,
    parse_root_blob,
)
from .formats.decode_kvtree import KVTreeDecodeError, decode_kvtree
from .formats.decode_revisions import decode_document_storage_revisions
from .formats.fsshttpb import (
    BLOBHEAP_MAGIC,
    DE_CELL_MANIFEST,
    DE_OBJECT_GROUP,
    DE_REVISION_MANIFEST,
    DataElement,
    ExGuid,
    FsshttpbDecodeError,
    parse_blobheap_record,
)
from .formats.fsshttpd import (
    PRIMARY_STREAM_ROOT_GUID,
    FsshttpdError,
    ObjectStore,
    infer_root_objects,
    primary_root_object,
    reassemble,
    salvage_zip_parts,
)
from .crypto.spookyhash import hash128_bytes
from .odc.syzygy_cluster_set import (
    BOOT_CLUSTER_SET_FILE_NAME,
    ClusterSetScan,
    decode_document_list,
    scan_cluster_set,
)
from .crypto.syzygy_crypt_session import parse_crypt_session_prefix, parse_crypto_xml, unwrap_stream_key
from .crypto.syzygy_encryption_providers import provider_name
from .crypto.syzygy_protected_stream import (
    ProtectedStreamDecodeError,
    decrypt_shard_unauthenticated,
    inspect_protected_stream,
    verify_shard_hmac,
)
from .crypto.syzygy_vault import decode_vault, decode_vault_sessions
from .formats.terse_codec import TerseDecodeError, TerseReader, decode_document_metadata, decode_envelope

MODES = ("b2", "b3", "cw")
PILE_MARKS_WITH_KVTREE = (0x96, 0x97)


PILE_MARKS_LEGACY_TERSE = (0x93, 0x94)
BLOCK_SIZE = 16
STANDARD_DPAPI_PROVIDER = "54bd1499-7413-472f-8835-d19454db7952"
NAME_TOKEN = re.compile(r"(?<![A-Z2-7])([A-H][A-Z2-7]{31})(?![A-Z2-7])")






CSI_CONTEXT_ID_DEFAULT = bytes.fromhex("73fc71c4ab513947a3806160fbe87162")
CSI_INDEX_ID_DEFAULT = bytes.fromhex("fe3b0402ce656648af946b061358e32c")


METADATA_KEY_NAMES = {
    0x16F5438B: "document_id",
    0x4F3636C8: "is_od_consumer_file_migrated",
    0x8009D64D: "base_cobalt_hash",
    0x410040CB: "server_version",
    0x5DB6380A: "file_saved_to_server",
    0x86AC511F: "last_server_file_modified_time",
    0xA3BE0E4: "last_file_modified_time",
    0xF8D55585: "file_create_time",


    0x9AF7E276: "last_file_accessed_time",
    0x9CF0A1D3: "document_storage_schema",
    0x2533FF5A: "cobalt_minor_version",
    0x98260CE8: "cobalt_major_version",
    0x9E230214: "endpoint_type",
}








PARTITION_COLUMN_KEYS = (
    (0x2CABC48D, 0xA78ACB51, 0x68A9D1FE, 0xE11CFB80, 0xECE441D3, 0x1C7CF937, 0x4465EF21,
     0x58BAE1AE, 0x3E4F8C23, 0xC94DA9DE, 0xD504C27A, 0xD0BBF55B, 0xDD87500B, 0xAA8C48B9,
     0x30F5EE3D, 0x78879736, 0xFFA07065, 0x896A8021, 0xC038E5A9, 0xE571E604, 0x525F3984,
     0x6F226B32, 0x58C9190A, 0xC51C8555, 0x2FC6644C, 0x5E3B225D, 0xFB0465C0, 0x88D2933C,
     0x80E3E085, 0x3CDB2403, 0x955AC3EC, 0x837AFE1F, 0xD8D2A659, 0xBFD2FC34, 0xE5946333),
    (0xD9B65BF5, 0x9FE7DDFB, 0xB13A0C51, 0x302D28C6, 0x610A6423, 0x43FD69CA, 0x376CA660,
     0x3BC12F69, 0x94589CC3, 0xCA32637D, 0x4ED381EC, 0xED822FFE, 0x13EBEB42, 0x7B796B0E,
     0xABD8D7AA, 0x9C6DA098, 0xB8561EFA, 0xC235CD8A, 0x9BEFF6DF, 0x52E7F557, 0x16D7E141,
     0xD705C6B6, 0xDB4D9F25, 0x940A5DDC, 0x9B7E8DE4, 0xFF970E81, 0xE6C612F4, 0xA3D7BE67,
     0xAB11B5BE, 0x96B5D01B, 0xFC9E5397, 0xAB5B3C67, 0x3DC8B5D7, 0xD602A0F9, 0x9D3B93B3),
    (0xACBFFE8B, 0xD96C911C, 0x072D6DDF, 0x270EC9A6, 0x61824E3E, 0x8D87CB59, 0x71CDFED7,
     0x13B5FB20, 0xA0858B71, 0xEE888C7B, 0x13EA3E8A, 0xCD670640, 0xE643B9F0, 0x5C1F2601,
     0x1626793C, 0x95D0DE1B, 0x5FC3B93B, 0xF08AAD93, 0x4EB4FC78, 0xFE3BE7BB, 0xFCC6AA4E,
     0x8D14156B, 0x82BDEA47, 0x3F57B8B8, 0x90245E95, 0x511F27F8, 0x6A06076E, 0x41E62756,
     0x1FC97B4B, 0x9A9177E1, 0x79BCDDA8, 0x02DB95EF, 0xC283A94E, 0xFC2DA1C7, 0xBDCD95A7),
)
PARTITION_COLUMN_NAMES = {
    0: "pending_upload",
    1: "pending_download",
    2: "mergeable_file_in_conflict",
    3: "working_branch_rid",
    4: "download_branch_rid",
    5: "upload_branch_rid",
    6: "base_branch_rid",
    11: "file_branch",
    12: "working_branch_dirty",
    13: "server_access_properties",
    14: "server_access_properties_2",
    25: "expected_file_etag",
    26: "server_etag",
    31: "mergeable_resolve_conflict_state",
    33: "download_in_progress",
    34: "working_branch_rid_last_content_change",
}





METADATA_EXGUID_KEY_NAMES = {
    0x01CB6A25: "unresolved_upload",
}

METADATA_COLUMN_BY_KEY = {
    key: (partition, column)
    for partition, keys in enumerate(PARTITION_COLUMN_KEYS)
    for column, key in enumerate(keys)
}


def _csi_record_family(payload: bytes) -> str:
    if CSI_CONTEXT_ID_DEFAULT in payload[:40] or CSI_INDEX_ID_DEFAULT in payload[:64]:
        return "csi_index_record (LIKELY)"
    if looks_like_hierarchy_payload(payload):
        return "csi_hierarchy_record"
    return "unknown"


VERIFIED_SIGNATURES = {"local_header", "data", "combined", "final", "rdc_md4"}
STRONG_TARGET_EVIDENCE = (
    "current_pile_cell_manifest",
    "current_pile_hierarchy",
    "current_pile_group_set (inferred)",
    "metadata_working_branch",
)


def reassembly_status(missing: list[str], signature_checks: list[str], zip_info: dict[str, Any]) -> str:


    if missing:
        return "partial"
    if "mismatch" in signature_checks:
        return "conflict"
    if signature_checks and set(signature_checks) <= VERIFIED_SIGNATURES and (
        zip_info.get("is_zip") or "rdc_md4" in signature_checks or "final" in signature_checks
    ):
        return "complete_candidate"
    return "complete_unverified_signatures"


COMPLETE_STATES = ("complete_candidate", "complete_unverified_signatures")
EVIDENCE_CLASSES = {
    "A": "current_state_evidence",
    "B": "latest_index_snapshot",
    "C": "revision_lineage (LIKELY)",
}


def _candidate_key(item: dict[str, Any]) -> str:
    hints = item.get("revision_id_hint") or []
    return hints[0] if len(hints) == 1 else f"inferred:{item.get('pile_id')}:{item.get('root_object')}"


_PARAGRAPH_RE = re.compile(r"<w:p[ >].*?</w:p>|<w:p/>", re.S)
_RUN_TEXT_RE = re.compile(r"<w:t(?:\s[^>]*)?>([^<]*)</w:t>|<w:t/>|<w:(tab|br|cr)\s*/>")


def document_paragraphs(xml: str) -> list[str]:


    paragraphs = []
    for paragraph in _PARAGRAPH_RE.findall(xml):
        chunks = []
        for m in _RUN_TEXT_RE.finditer(paragraph):
            if m.group(1) is not None:
                chunks.append(html.unescape(m.group(1)))
            elif m.group(2) == "tab":
                chunks.append("\t")
            elif m.group(2) in ("br", "cr"):
                chunks.append("\n")
        paragraphs.append("".join(chunks))
    return paragraphs


def partial_text_report(xml: str, revision: str, crc32: str, parts: list[dict[str, Any]]) -> str:


    present = sorted({p.get("name", "?") for p in parts})
    header = [
        "CacheWeave partial recovery (README 6.4, salvaged parts). This is NOT the original document file.",
        f"Text of the verified word/document.xml (ZIP CRC-32 {crc32}) attributed to revision {revision}.",
        "The evidence names this revision as the current state, but it cannot be rebuilt whole, so the target is undetermined.",
        "Verified parts of this revision: " + ", ".join(present) + ". Any other part of the document is missing.",
        "Only text runs are shown: no formatting, pictures, or fields.",
        "-" * 72,
    ]
    return "\n".join(header + document_paragraphs(xml)) + "\n"


def collect_candidates(
    revisions_out: list[dict[str, Any]], inferred_out: list[dict[str, Any]]
) -> tuple[dict[str, dict[str, Any]], set[str]]:


    candidates: dict[str, dict[str, Any]] = {}
    non_document: set[str] = set()
    for item in list(revisions_out) + list(inferred_out):
        if item.get("status") not in COMPLETE_STATES:
            continue
        key = item["revision_id"] if "revision_id" in item else _candidate_key(item)
        if not item.get("zip", {}).get("is_zip"):
            if not key.startswith("inferred:"):
                non_document.add(key)
            continue
        source = item.get("source", "revision_manifest")
        existing = candidates.get(key)
        if existing is None:
            candidates[key] = {"sha256": item["sha256"], "sources": [source]}
        elif existing["sha256"] == item["sha256"]:
            existing["sources"] = sorted(set(existing["sources"]) | {source})
        else:
            existing.setdefault("conflicting_reconstructions", []).append({"sha256": item["sha256"], "source": source})
    return candidates, non_document


def _later_revisions(revision: str, lineage: dict[str, Any] | None) -> set[str]:
    later: set[str] = set()
    stack = [revision]
    edges = (lineage or {}).get("edges", [])
    while stack:
        current = stack.pop()
        for edge in edges:
            if edge["earlier"] == current and edge["later"] not in later:
                later.add(edge["later"])
                stack.append(edge["later"])
    return later


def _earlier_revisions(revision: str, lineage: dict[str, Any] | None) -> set[str]:
    earlier: set[str] = set()
    stack = [revision]
    edges = (lineage or {}).get("edges", [])
    while stack:
        current = stack.pop()
        for edge in edges:
            if edge["later"] == current and edge["earlier"] not in earlier:
                earlier.add(edge["earlier"])
                stack.append(edge["earlier"])
    return earlier


def _session_and_number(revision: str) -> tuple[str, int] | None:
    match = re.match(r"^\{([0-9a-fA-F-]{36})\},(\d+)$", revision)
    return (match.group(1).lower(), int(match.group(2))) if match else None


def unordered_rivals(revision: str, candidates: dict[str, dict[str, Any]], lineage: dict[str, Any] | None) -> list[str]:


    earlier = _earlier_revisions(revision, lineage)
    mine = _session_and_number(revision)
    digest = (candidates.get(revision) or {}).get("sha256")
    rivals = []
    for other, value in candidates.items():
        if other == revision or other in earlier or value.get("sha256") == digest:
            continue
        theirs = _session_and_number(other)
        if mine and theirs and theirs[0] == mine[0] and theirs[1] < mine[1]:
            continue
        rivals.append(other)
    return sorted(rivals)


def select_target(
    claims: dict[str, dict[str, set[str]]],
    candidates: dict[str, dict[str, Any]],
    lineage: dict[str, Any] | None,
    orphan_namespaces: list[str],
) -> dict[str, Any]:


    for cls, basis in EVIDENCE_CLASSES.items():
        named = claims.get(cls) or {}
        if not named:
            continue
        if cls != "A" and orphan_namespaces:
            return {
                "status": "undetermined",
                "basis": basis,
                "reason": "surviving object groups belong to a revision that no manifest or hierarchy record describes",
                "orphan_namespaces": orphan_namespaces,
                "named": {r: sorted(s) for r, s in named.items()},
            }
        if len(named) > 1:
            return {
                "status": "ambiguous",
                "basis": basis,
                "reason": "the evidence names more than one revision",
                "candidates": {
                    r: {"evidence": sorted(s), **candidates.get(r, {"reconstructable": False})}
                    for r, s in sorted(named.items())
                },
            }
        revision, sources = next(iter(named.items()))
        if revision not in candidates:
            return {
                "status": "undetermined",
                "basis": basis,
                "reason": "the evidence names a revision that cannot be rebuilt",
                "named_revision": revision,
                "evidence": sorted(sources),
                "candidates": sorted(candidates),
            }
        value = candidates[revision]
        newer = sorted(_later_revisions(revision, lineage))
        if value.get("conflicting_reconstructions") or newer:
            return {
                "status": "ambiguous",
                "basis": basis,
                "reason": "newer revisions build on the named one" if newer else "reconstructions disagree",
                "named_revision": revision,
                "newer_revisions": newer,
                "candidates": {
                    revision: {"evidence": sorted(sources), **value},
                    **{r: candidates.get(r, {"reconstructable": False}) for r in newer},
                },
            }
        rivals = unordered_rivals(revision, candidates, lineage) if cls != "A" else []
        if rivals:
            return {
                "status": "ambiguous",
                "basis": basis,
                "reason": "another rebuildable revision is not shown to be older than the named one",
                "named_revision": revision,
                "unordered_rivals": rivals,
                "candidates": {
                    revision: {"evidence": sorted(sources), **value},
                    **{r: candidates[r] for r in rivals},
                },
            }
        corroboration = {
            EVIDENCE_CLASSES[other]: sorted(claims[other][revision])
            for other in EVIDENCE_CLASSES
            if other != cls and revision in (claims.get(other) or {})
        }
        return {
            "status": "selected",
            "basis": basis,
            "revision_id": revision,
            "evidence": sorted(sources),
            "corroboration": corroboration,
            **value,
        }
    return {"status": "undetermined", "reason": "no current-state evidence survives", "candidates": sorted(candidates)}


def _exguid_from_text(text: str) -> ExGuid:
    guid, _, value = text[1:].partition("},")
    return ExGuid(guid, int(value))


def _namespace_of(exguid_text: str) -> str:
    return exguid_text[1:].split("}", 1)[0]


def lineage_head_claims(heads: list[str], known: set[str], non_document: set[str]) -> list[str]:


    def split(revision: str) -> tuple[str, int] | None:
        match = re.match(r"^\{([0-9a-fA-F-]{36})\},(\d+)$", revision)
        return (match.group(1).lower(), int(match.group(2))) if match else None

    documents = [split(r) for r in known if r not in non_document]
    kept = []
    for head in heads:
        if head in non_document:
            continue
        parts = split(head)
        if parts and any(d and d[0] == parts[0] and d[1] > parts[1] for d in documents):
            continue
        kept.append(head)
    return kept


def revision_lineage(revision_groups: dict[str, set[str]]) -> dict[str, Any]:


    namespaces = {revision: _namespace_of(revision) for revision in revision_groups}
    successors: dict[str, set[str]] = {revision: set() for revision in revision_groups}
    for later, groups in revision_groups.items():
        group_namespaces = {_namespace_of(group) for group in groups}
        for earlier in revision_groups:
            if namespaces[earlier] != namespaces[later] and namespaces[earlier] in group_namespaces:
                successors[earlier].add(later)
    neighbours = {revision: set(after) for revision, after in successors.items()}
    for revision, after in successors.items():
        for other in after:
            neighbours[other].add(revision)
    heads, seen = [], set()
    for start in sorted(revision_groups):
        if start in seen:
            continue
        component, stack = set(), [start]
        while stack:
            revision = stack.pop()
            if revision not in component:
                component.add(revision)
                stack.extend(neighbours[revision] - component)
        seen |= component
        indegree = {r: sum(r in successors[o] for o in component) for r in component}
        queue = [r for r in component if indegree[r] == 0]
        ordered = 0
        while queue:
            revision = queue.pop()
            ordered += 1
            for other in successors[revision]:
                indegree[other] -= 1
                if indegree[other] == 0:
                    queue.append(other)
        tips = [r for r in component if not successors[r]]
        if ordered == len(component) and len(tips) == 1:
            heads.append(tips[0])
    edges = sorted((earlier, later) for earlier, after in successors.items() for later in after)
    return {"edges": [{"earlier": a, "later": b} for a, b in edges], "heads": sorted(heads)}


def metadata_exguid_references(elements: list[Any]) -> list[dict[str, Any]]:


    references = []
    for element in elements:
        value = element.value
        if isinstance(value, str):
            try:
                value = bytes.fromhex(value)
            except ValueError:
                continue
        if not isinstance(value, (bytes, bytearray)) or len(value) != 20:
            continue
        guid = str(uuid.UUID(bytes_le=bytes(value[:16])))
        number = struct.unpack_from("<I", value, 16)[0]
        if guid == "00000000-0000-0000-0000-000000000000":
            continue
        partition_column = METADATA_COLUMN_BY_KEY.get(element.key)
        if partition_column:
            column_name = PARTITION_COLUMN_NAMES.get(partition_column[1])
        else:
            column_name = METADATA_EXGUID_KEY_NAMES.get(element.key)
        references.append(
            {
                "key": f"0x{element.key:08x}",
                "partition": partition_column[0] if partition_column else (0 if column_name else None),
                "column": partition_column[1] if partition_column else None,
                "column_name": column_name,
                "exguid": f"{{{guid}}},{number}",
            }
        )
    return references


def upload_state(references: list[dict[str, Any]]) -> dict[str, Any] | None:


    p0 = {r["column_name"]: r["exguid"] for r in references if r.get("partition") == 0 and r.get("column_name")}
    working, base, upload = p0.get("working_branch_rid"), p0.get("base_branch_rid"), p0.get("upload_branch_rid")
    if not working:
        return None
    if upload is None and base == working:
        state = "settled"
    elif upload == working and base != working:
        state = "upload_not_confirmed"
    else:
        state = "other"
    return {"state": state, "working": working, "base": base, "upload": upload}


@dataclass
class SessionKey:
    session_id: int
    stream_key: bytes
    stream_salt: bytes
    verifier_valid: bool


@dataclass
class FileEntry:
    path: Path
    name: str
    data: bytes
    kind: str
    name_id: str | None
    native_name: bool
    mtime_ns: int | None = None


@dataclass
class BlobResult:
    name: str
    path: str
    name_id: str | None
    native_name: bool
    identifier: str | None = None
    status: str = "pending"
    detail: str = ""
    logical_size: int | None = None
    plaintext: bytes | None = None
    payload_kind: str | None = None
    data_elements: list[DataElement] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    id_matches_content: bool | None = None
    identity_source: str = "name"






def dpapi_unprotect(blob: bytes) -> bytes:


    import ctypes
    import ctypes.wintypes as wintypes

    class DataBlob(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]

    buffer = ctypes.create_string_buffer(blob, len(blob))
    source = DataBlob(len(blob), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_char)))
    target = DataBlob()
    if not ctypes.windll.crypt32.CryptUnprotectData(
        ctypes.byref(source), None, None, None, None, 0x1, ctypes.byref(target)
    ):
        raise OSError(ctypes.GetLastError(), "CryptUnprotectData failed")
    try:
        return ctypes.string_at(target.pbData, target.cbData)
    finally:
        ctypes.windll.kernel32.LocalFree(target.pbData)


def dpapi_blob_header(blob: bytes) -> dict[str, Any]:
    if len(blob) < 52:
        return {"valid": False}
    flags = struct.unpack_from("<I", blob, 40)[0]
    return {
        "valid": blob[4:20] == uuid.UUID("df9d8cd0-1501-11d1-8c7a-00c04fc297eb").bytes_le,
        "master_key_guid": str(uuid.UUID(bytes_le=blob[24:40])),
        "flags": f"0x{flags:x}",
        "scope": "machine" if flags & 0x4 else "user",
    }


def load_sessions(vault_value: bytes, key_source: str, report: dict[str, Any]) -> dict[int, SessionKey]:
    vault = decode_vault(vault_value)
    info: dict[str, Any] = {
        "providers": [
            {"id": provider_id, "name": provider_name(provider_id)}
            for provider_id in vault.provider_ids
        ],
        "key_source": key_source.split(":", 1)[0],
    }
    report["vault"] = info
    if vault.provider_ids == (STANDARD_DPAPI_PROVIDER,):
        info["dpapi"] = dpapi_blob_header(vault.sessions_blob)
    if key_source == "none":
        info["status"] = "no_key_source"
        return {}
    try:
        if key_source == "live" or key_source.startswith("live-export:"):
            if vault.provider_ids != (STANDARD_DPAPI_PROVIDER,):
                raise ValueError("live key source supports only the standard DPAPI provider")
            plaintext = dpapi_unprotect(vault.sessions_blob)
            if key_source.startswith("live-export:"):


                try:
                    with open(key_source.split(":", 1)[1], "xb") as export:
                        export.write(plaintext)
                    info["export"] = "written"
                except FileExistsError:
                    info["export"] = "refused: the file exists"
        elif key_source.startswith("sessions:"):
            plaintext = Path(key_source.split(":", 1)[1]).read_bytes()
        elif key_source.startswith("offline:") or key_source.startswith("offline-files:"):
            from .crypto.dpapi_offline import OfflineMachineDpapi

            if vault.provider_ids != (STANDARD_DPAPI_PROVIDER,):
                raise ValueError("offline DPAPI supports only the standard DPAPI provider")
            if key_source.startswith("offline:"):
                dpapi = OfflineMachineDpapi.from_windows_root(Path(key_source.split(":", 1)[1]))
            else:
                parts = dict(item.split("=", 1) for item in key_source.split(":", 1)[1].split(","))
                dpapi = OfflineMachineDpapi(
                    Path(parts["system"]), Path(parts["security"]), Path(parts["masterkeys"])
                )
            plaintext = dpapi.unprotect(vault.sessions_blob)
            info["offline_dpapi"] = dpapi.log
        else:
            raise ValueError(f"unknown key source {key_source!r}")
        sessions = decode_vault_sessions(plaintext).sessions
    except (OSError, ValueError, KeyError) as error:
        info["status"] = f"failed: {type(error).__name__}: {error}"
        return {}
    keys = {}
    for session in sessions:
        prefix = parse_crypt_session_prefix(session.serialized_value)
        unwrapped = unwrap_stream_key(session.secret, parse_crypto_xml(prefix.crypto_xml))
        keys[session.session_id] = SessionKey(
            session.session_id,
            unwrapped.stream_key,
            unwrapped.stream_salt,
            unwrapped.verifier_valid,
        )
    info["status"] = "ok"
    info["sessions"] = [
        {"session_id": key.session_id, "verifier_valid": key.verifier_valid} for key in keys.values()
    ]
    return keys






def name_identifier(name: str) -> str | None:


    for match in NAME_TOKEN.finditer(name):
        try:
            return decode_syzygy_identifier(match.group(1)).hex()
        except ValueError:
            continue
    return None


def classify(data: bytes) -> str:




    if data and any(data[offset] == 0x75 for offset in range(0, len(data), 0x1000)):
        try:
            scan = scan_cluster_set(data)
            if scan.records:
                return "cluster_set"
        except Exception:
            pass
    try:
        inspect_protected_stream(data, BLOCK_SIZE)
        return "protected_stream"
    except (ProtectedStreamDecodeError, ValueError):
        pass
    if len(data) > 6 and data[0] in PILE_MARKS_WITH_KVTREE and data[1] == 0x69:
        return "pile"
    if len(data) > 10 and data[0] in PILE_MARKS_LEGACY_TERSE and data[1] == 0x02:
        try:
            parse_legacy_pile(data)
            return "pile"
        except (TerseDecodeError, ValueError):
            pass
    return "unknown"


def _native_name(kind: str, name: str, identifier: str | None) -> bool:
    if kind == "cluster_set":
        return name == BOOT_CLUSTER_SET_FILE_NAME
    if identifier is None:
        return False
    token = encode_syzygy_identifier(bytes.fromhex(identifier))
    if kind == "pile":
        return name == f"{token}.P"
    if kind == "protected_stream":
        return name == f"e_{token}.R"
    return False


ARX_VOLUME_NAME = "0.ARX"
FILETIME_UNIX_EPOCH = 116444736000000000


def inventory_namespace(ns_dir: Path, arx_report: dict[str, Any] | None = None) -> list[FileEntry]:

    entries = []
    for path in sorted(p for p in ns_dir.iterdir() if p.is_file()):
        data = path.read_bytes()
        if path.name.upper() == ARX_VOLUME_NAME:
            try:
                files, summary = extract_volume_files(data, include_stale=True)
            except ArxDecodeError as error:
                if arx_report is not None:
                    arx_report.update({"volume": path.name, "error": str(error)})
                continue
            if arx_report is not None:
                arx_report.update({"volume": path.name, **summary})
            for item in files:
                kind = classify(item.data)
                identifier = name_identifier(item.name)
                mtime = None if item.last_write_time is None else (item.last_write_time - FILETIME_UNIX_EPOCH) * 100
                where = path / "stale" / item.name if item.stale else path / item.name
                entries.append(FileEntry(where, item.name, item.data, kind, identifier,
                                         _native_name(kind, item.name, identifier), mtime))
            continue
        kind = classify(data)
        identifier = name_identifier(path.name)
        entries.append(FileEntry(path, path.name, data, kind, identifier, _native_name(kind, path.name, identifier)))
    return entries


def decrypt_blob(data: bytes, keys: dict[int, SessionKey]) -> tuple[str, str, bytes | None]:
    try:
        layout = inspect_protected_stream(data, BLOCK_SIZE)
    except (ProtectedStreamDecodeError, ValueError) as error:
        return "malformed", str(error), None
    if not layout.shards:
        return "ok", "empty stream", b""
    session_id = layout.shards[0].footer.session_id
    key = keys.get(session_id)
    if key is None:
        return "no_key", f"session {session_id}", None
    parts = []
    for shard in layout.shards:
        ciphertext = data[shard.physical_offset : shard.physical_offset + shard.encrypted_size]
        if shard.footer.session_id != session_id or not verify_shard_hmac(
            shard, ciphertext, key.stream_key, key.stream_salt
        ):
            return "hmac_fail", f"shard {shard.index}", None
        parts.append(
            decrypt_shard_unauthenticated(shard, ciphertext, key.stream_key, key.stream_salt)
        )
    return "ok", f"{len(layout.shards)} shard(s)", b"".join(parts)


def parse_legacy_pile(data: bytes) -> dict[str, dict[str, Any]]:

    mark = data[0]
    payload = decode_envelope(data[1:]).payload
    reader = TerseReader(payload)
    count = reader.read_uleb128(16)
    if count > len(data):
        raise TerseDecodeError("too many entries in pile")
    entries: dict[str, dict[str, Any]] = {}
    for _ in range(count):
        name = reader.read_byte_vector()
        if reader.read_uleb128(32) != 16:
            raise TerseDecodeError("pile entry hash is not 16 bytes")
        blob = reader.read_exact(16)
        attributes = reader.read_byte_vector()
        flags = reader.read_exact(1)[0] if mark == 0x94 else 0
        entries[name.decode("latin1")] = {"blob": blob.hex(), "attributes": {"0": attributes.hex(), "1": flags, "2": 0}}
    if not reader.finished:
        raise TerseDecodeError("trailing bytes after the pile entries")
    return entries


def parse_pile(data: bytes) -> dict[str, Any]:
    if data and data[0] in PILE_MARKS_LEGACY_TERSE:
        return {"mark": f"0x{data[0]:02x}", "entries": parse_legacy_pile(data), "legacy_terse": True}
    tree = decode_kvtree(data[1:])
    entries = {}
    for child in tree.children:
        key = child.key.value
        key = key if isinstance(key, (bytes, bytearray)) else bytes.fromhex(key)
        value = child.value.value
        value = value.hex() if isinstance(value, (bytes, bytearray)) else value
        attributes = {}
        for sub in child.children:
            sub_value = sub.value.value
            attributes[str(sub.key.value)] = (
                sub_value.hex() if isinstance(sub_value, (bytes, bytearray)) else sub_value
            )
        entries[bytes(key).decode("latin1")] = {"blob": value, "attributes": attributes}
    return {"mark": f"0x{data[0]:02x}", "entries": entries}


def describe_zip(data: bytes) -> dict[str, Any]:
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
        bad = archive.testzip()
        return {"is_zip": True, "crc_ok": bad is None, "first_bad": bad, "entries": archive.namelist()}
    except zipfile.BadZipFile as error:
        return {"is_zip": False, "error": str(error)}


AUX_STREAM_MAGIC = bytes.fromhex("1a5a3a30")


def describe_auxiliary_stream(payload: bytes) -> dict[str, Any]:


    import zlib

    if payload[:4] != AUX_STREAM_MAGIC or len(payload) < 8:
        return {"kind": "unknown", "head": payload[:8].hex()}
    try:
        decompressor = zlib.decompressobj(-15)
        text = decompressor.decompress(payload[8:]).decode("utf-8-sig", "replace")
    except zlib.error as error:
        return {"kind": "deflate_header_unreadable", "error": str(error)}
    root = re.search(r"<([A-Za-z]+)[\s>]", text.split("?>", 1)[-1])
    result: dict[str, Any] = {
        "kind": "deflated_xml",
        "header": payload[:8].hex(),
        "xml_root": root.group(1) if root else None,
        "xml_size": len(text.encode("utf-8")),
    }
    if result["xml_root"] == "EditorsTable":
        result["editor_count"] = text.count("<Editor>")
        result["xml"] = text
    return result


def _classify_plaintext(blob: BlobResult) -> None:
    plaintext = blob.plaintext or b""
    if plaintext[:4] == struct.pack("<I", BLOBHEAP_MAGIC):
        try:
            blob.data_elements = parse_blobheap_record(plaintext).elements
            blob.payload_kind = "fsshttpb:" + ",".join(e.type_name for e in blob.data_elements)
        except FsshttpbDecodeError as error:
            blob.payload_kind = f"blobheap_unparsed: {error}"
    elif plaintext[:1] == b"\x02":
        try:
            envelope = decode_envelope(plaintext)
            blob.payload_kind = f"terse_v2:{envelope.payload_size}:{_csi_record_family(envelope.payload)}"
        except TerseDecodeError:
            blob.payload_kind = "unknown"
    elif plaintext[:16] == ROOT_BLOB_SIGNATURE:
        try:
            parse_root_blob(plaintext)
            blob.payload_kind = "csi_root_blob"
        except BlobHeapDecodeError as error:
            blob.payload_kind = f"csi_root_blob_unparsed: {error}"
    else:
        blob.payload_kind = f"unknown:{plaintext[:2].hex()}"






def read_resident_properties(scan: ClusterSetScan, report: dict[str, Any]) -> list[dict[str, Any]]:


    report["cluster_set"] = scan.to_json_dict()
    metadata = scan.by_label("DocumentMetadata")
    if metadata is not None:
        try:
            elements = decode_document_metadata(metadata.value).elements
            report["document_metadata"] = {
                "generation": metadata.generation,
                "element_count": len(elements),
                "named": {METADATA_KEY_NAMES[e.key]: e.value for e in elements if e.key in METADATA_KEY_NAMES},
                "urls": sorted(
                    {e.value for e in elements if isinstance(e.value, str) and e.value.startswith("http")}
                ),
                "revision_references": metadata_exguid_references(elements),
            }
            unresolved = [r["exguid"] for r in report["document_metadata"]["revision_references"]
                          if r["column_name"] == "unresolved_upload"]
            if unresolved:
                report["document_metadata"]["unresolved_upload"] = unresolved[0]
            state = upload_state(report["document_metadata"]["revision_references"])
            if state:
                report["document_metadata"]["upload_state"] = state
        except Exception as error:
            report["document_metadata"] = {"generation": metadata.generation, "error": str(error)}
    revision_id = next((r.cluster_id for r in scan.records if r.label == "DocumentStorageRevisions"), None)
    storage_revisions = []
    for record in scan.generations(revision_id) if revision_id is not None else []:
        try:
            decoded = decode_document_storage_revisions(record.value)
        except Exception as error:
            storage_revisions.append({"generation": record.generation, "error": str(error)})
            continue
        entries = []
        for revision in decoded.revisions:
            props = {
                p.name: (p.value.hex() if isinstance(p.value, (bytes, bytearray)) else p.value)
                for p in revision.properties
            }
            entries.append({"storage_revision_id": revision.storage_revision_id, **props})
        storage_revisions.append({"generation": record.generation, "revisions": entries})
    report["storage_revisions"] = storage_revisions
    document_list = scan.by_label("DocumentList")
    if document_list is not None:
        try:
            version, documents = decode_document_list(document_list.value)
            report["document_list"] = {
                "version": version,
                "documents": [str(uuid.UUID(bytes_le=d.document_id)) for d in documents],
            }
        except Exception as error:
            report["document_list"] = {"error": str(error)}
    return storage_revisions


def _native_current_manifest(
    pile: dict[str, Any] | None, by_id: dict[str, BlobResult], elements: list[DataElement]
) -> dict[str, Any]:


    if pile is None:
        return {"status": "failed", "reason": "current dictionary pile unavailable"}
    item = pile["entries"].get("indexEntries")
    blob = by_id.get(item["blob"]) if item else None
    if blob is None or blob.status != "ok":
        return {"status": "failed", "reason": "indexEntries record unavailable"}
    try:
        storage_index = parse_index_entries(blob.plaintext).storage_index()
    except BlobHeapDecodeError as error:
        return {"status": "failed", "reason": f"indexEntries undecodable: {error}"}
    by_exguid = {str(e.exguid): e for e in elements}
    cells = storage_index["cells"]
    if len(cells) != 1:
        return {"status": "failed", "reason": f"expected one cell mapping, found {len(cells)}"}
    cell_manifest_id = next(iter(cells.values()))
    cell_manifest = by_exguid.get(cell_manifest_id)
    if cell_manifest is None or cell_manifest.type != DE_CELL_MANIFEST:
        return {"status": "failed", "reason": f"cell manifest {cell_manifest_id} unavailable"}
    revision = str(cell_manifest.current_revision)
    manifest_id = storage_index["revisions"].get(revision)
    if manifest_id is None or manifest_id not in by_exguid:
        return {
            "status": "failed",
            "reason": f"revision manifest for {revision} unavailable",
            "current_revision": revision,
        }
    return {
        "status": "ok",
        "storage_manifest": storage_index["storage_manifest"],
        "cell_manifest": cell_manifest_id,
        "current_revision": revision,
        "revision_manifest": manifest_id,
    }


def _current_pile_id(storage_revisions: list[dict[str, Any]]) -> str | None:
    for generation in reversed(storage_revisions):
        revisions = generation.get("revisions") or []
        if revisions and revisions[-1].get("dictionary_pile_id"):
            return revisions[-1]["dictionary_pile_id"]
    return None






def process_namespace(ns_dir: Path, key_source: str, out_dir: Path | None, mode: str = "cw") -> dict[str, Any]:
    if mode not in MODES:
        raise ValueError(f"mode must be one of {MODES}")
    report: dict[str, Any] = {"namespace": ns_dir.name, "mode": mode}
    try:
        report["namespace_id"] = str(uuid.UUID(bytes_le=decode_syzygy_identifier(ns_dir.name)))
    except ValueError as error:
        report["namespace_id_error"] = str(error)

    arx_report: dict[str, Any] = {}
    entries = inventory_namespace(ns_dir, arx_report)
    if arx_report:
        report["arx_volume"] = arx_report
    report["inventory"] = [
        {
            "name": e.name,
            "size": len(e.data),
            "sha256": hashlib.sha256(e.data).hexdigest(),
            "kind": e.kind,
            "identifier": e.name_id,
            "native_name": e.native_name,
            "name_suggests": {".C4": "cluster_set", ".P": "pile", ".R": "protected_stream"}.get(
                e.path.suffix, "unknown"
            ),
        }
        for e in entries
    ]



    native_only = mode == "b2"
    structure_scan = mode in ("b3", "cw")

    def usable(entry: FileEntry, kind: str) -> bool:
        return entry.kind == kind and (entry.native_name or not native_only)


    keys: dict[int, SessionKey] = {}
    storage_revisions: list[dict[str, Any]] = []
    scans = [scan_cluster_set(e.data) for e in entries if usable(e, "cluster_set")]
    scan = max(scans, key=lambda s: len(s.records)) if scans else None
    blob_entries = [e for e in entries if usable(e, "protected_stream")]
    if scan is not None:
        storage_revisions = read_resident_properties(scan, report)
        vault = scan.by_label("_vault")
        if vault is not None and blob_entries:
            keys = load_sessions(vault.value, key_source, report)
    current_pile_id = _current_pile_id(storage_revisions)
    report["current_pile_id"] = current_pile_id


    piles: dict[str, dict[str, Any]] = {}
    for entry in entries:
        if not usable(entry, "pile"):
            continue
        try:
            pile = parse_pile(entry.data)
        except (KVTreeDecodeError, ValueError) as error:
            report.setdefault("pile_errors", []).append({"name": entry.name, "error": str(error)})
            continue
        pile["mtime_ns"] = entry.mtime_ns if entry.mtime_ns is not None else entry.path.stat().st_mtime_ns
        pile["file"] = entry.name
        piles[entry.name_id or entry.name] = pile
    if mode == "b2":
        piles = {pid: p for pid, p in piles.items() if pid == current_pile_id}


    blobs: list[BlobResult] = []
    for entry in blob_entries:
        blob = BlobResult(entry.name, str(entry.path), entry.name_id, entry.native_name)
        blob.status, blob.detail, blob.plaintext = decrypt_blob(entry.data, keys)
        if blob.plaintext is not None:
            blob.logical_size = len(blob.plaintext)
            content_id = hash128_bytes(blob.plaintext).hex()
            blob.id_matches_content = blob.name_id == content_id
            if blob.id_matches_content:
                blob.identifier, blob.identity_source = blob.name_id, "name+content"
            elif structure_scan:
                blob.identifier, blob.identity_source = content_id, "content"
            else:
                blob.identifier, blob.identity_source = blob.name_id, "name_unverified"
            _classify_plaintext(blob)
        else:
            blob.identifier = blob.name_id
        blobs.append(blob)
    by_id = {b.identifier: b for b in blobs if b.identifier}

    ordered_piles = sorted(piles.items(), key=lambda item: item[1]["mtime_ns"])
    for pile_id, pile in ordered_piles:
        pile["is_current"] = pile_id == current_pile_id
        for entry_name, item in pile["entries"].items():
            target = by_id.get(item["blob"])
            item["resolved"] = target is not None and target.status == "ok"
            if target is not None:
                target.references.append(f"{'current' if pile['is_current'] else 'older'}:{entry_name}")
    def _max_sequence(pile: dict[str, Any]) -> int:
        best = -1
        for item in pile["entries"].values():
            raw = item["attributes"].get("0")
            if isinstance(raw, str):
                try:
                    best = max(best, parse_blob_attributes(bytes.fromhex(raw)).sequence)
                except (BlobHeapDecodeError, ValueError):
                    pass
        return best

    report["piles"] = [
        {
            "pile_id": pile_id,
            "file": pile["file"],
            "mark": pile["mark"],
            "is_current": pile["is_current"],
            "entry_count": len(pile["entries"]),
            "max_blob_sequence": _max_sequence(pile),
            "unresolved": [n for n, e in pile["entries"].items() if not e["resolved"]],
        }
        for pile_id, pile in ordered_piles
    ]


    if structure_scan:
        visible = [b for b in blobs if b.status == "ok"]
    else:
        visible = [b for b in blobs if b.status == "ok" and b.references]
    elements: list[DataElement] = [e for blob in visible for e in blob.data_elements]
    element_owner = {str(e.exguid): blob for blob in visible for e in blob.data_elements}
    store = ObjectStore(elements)
    current_revisions = set()
    for element in elements:
        if element.type == DE_CELL_MANIFEST:
            owner = element_owner.get(str(element.exguid))
            if owner and any(ref.startswith("current:") for ref in owner.references):
                current_revisions.add(str(element.current_revision))
    metadata_refs = report.get("document_metadata", {}).get("revision_references", []) if structure_scan else []
    working_branch = {
        ref["exguid"] for ref in metadata_refs if ref["partition"] == 0 and ref["column"] == 3
    }


    snapshots = []
    for blob in blobs if mode == "cw" else []:
        if blob.status != "ok" or not (blob.payload_kind or "").endswith("csi_index_record (LIKELY)"):
            continue
        try:
            snapshot = parse_index_entries(blob.plaintext)
        except BlobHeapDecodeError as error:
            snapshots.append({"blob": blob.name, "error": str(error)})
            continue
        blob.payload_kind = "csi_index_entries"
        snapshots.append(
            {
                "blob": blob.name,
                "referenced_by": sorted({r.split(":", 1)[0] for r in blob.references}) or ["none"],
                "max_sequence": snapshot.max_sequence,
                **snapshot.storage_index(),
            }
        )
    report["storage_index_snapshots"] = sorted(snapshots, key=lambda s: s.get("max_sequence", -1))



    hierarchies: list[tuple[BlobResult, HierarchySnapshot]] = []
    hierarchy_current_revisions: set[str] = set()
    if mode == "cw":
        present_groups = {str(e.exguid): e for e in elements if e.type == DE_OBJECT_GROUP}
        hierarchy_report = []
        for blob in blobs:
            if blob.status != "ok" or not (blob.payload_kind or "").endswith("csi_hierarchy_record"):
                continue
            try:
                hierarchy = parse_hierarchy_record(blob.plaintext)
            except BlobHeapDecodeError as error:
                hierarchy_report.append({"blob": blob.name, "error": str(error)})
                continue
            hierarchies.append((blob, hierarchy))
            matching = mismatching = 0
            for node in hierarchy.of_type(NODE_OBJECT_GROUP):
                element = present_groups.get(node.exguid)
                if element is None:
                    continue
                try:
                    same = {str(o) for o in element.object_map()} == set(node.objects)
                except FsshttpbDecodeError:
                    continue
                matching, mismatching = matching + same, mismatching + (not same)
            cell_revisions = hierarchy.current_revisions()
            in_current_pile = any(r.startswith("current:") for r in blob.references)
            if in_current_pile and len(cell_revisions) == 1:
                hierarchy_current_revisions |= cell_revisions
            node_counts: dict[str, int] = {}
            for node in hierarchy.nodes:
                node_counts[node.type_name] = node_counts.get(node.type_name, 0) + 1
            hierarchy_report.append(
                {
                    "blob": blob.name,
                    "referenced_by": sorted({r.split(":", 1)[0] for r in blob.references}) or ["none"],
                    "pile_sequences": sorted(int(r.rsplit(":", 1)[1]) for r in blob.references if ":bsn:" in r),
                    "nodes": node_counts,
                    "cell_manifest_revisions": sorted(cell_revisions),
                    "revisions": [
                        {
                            "revision_id": n.revision_id,
                            "base_revision_id": n.base_revision_id,
                            "root_declarations": len(n.revision_roots),
                            "object_groups": len(n.references),
                        }
                        for n in hierarchy.of_type(NODE_REVISION_MANIFEST)
                    ],
                    "group_consistency": {"matching": matching, "mismatching": mismatching},
                }
            )
        report["hierarchy_records"] = hierarchy_report





        root_report = []
        element_serial_guids: dict[str, int] = {}
        for element in elements:
            if element.serial is not None:
                element_serial_guids[element.serial.guid] = element_serial_guids.get(element.serial.guid, 0) + 1
        for blob in blobs:
            if blob.status != "ok" or blob.payload_kind != "csi_root_blob":
                continue
            root = parse_root_blob(blob.plaintext)
            root_report.append(
                {
                    "blob": blob.name,
                    "referenced_by": sorted({r.split(":", 1)[0] for r in blob.references}) or ["none"],
                    "version": root.version,
                    "compatibility": root.compatibility,
                    "knowledge_guid": root.knowledge_guid,
                    "aggregate_cant_supply_knowledge": root.aggregate_cant_supply_knowledge,
                    "elements_with_this_serial_base": element_serial_guids.get(root.knowledge_guid, 0),
                }
            )
        report["root_blobs"] = root_report

    manifests = [e for e in elements if e.type == DE_REVISION_MANIFEST]
    if mode == "b2":
        native = _native_current_manifest(piles.get(current_pile_id) if current_pile_id else None, by_id, elements)
        report["native_path"] = native
        manifests = [m for m in manifests if str(m.exguid) == native.get("revision_manifest")]
        if native.get("current_revision"):
            current_revisions = {native["current_revision"]}
    revisions_out = []
    for manifest in manifests:
        owner = element_owner.get(str(manifest.exguid))
        entry: dict[str, Any] = {
            "source": "revision_manifest",
            "revision_id": str(manifest.revision_id),
            "base_revision_id": str(manifest.base_revision_id),
            "manifest_blob": owner.name if owner else None,
            "indexed_by_piles": sorted({ref.split(":", 1)[0] for ref in (owner.references if owner else [])}),
            "is_current": str(manifest.revision_id) in current_revisions,
            "metadata_columns": [
                f"p{ref['partition']}c{ref['column']}:{ref['column_name'] or ref['key']}"
                for ref in metadata_refs
                if ref["exguid"] == str(manifest.revision_id)
            ],
            "object_groups": len(manifest.object_group_references),
        }
        if owner and entry["metadata_columns"] and not owner.references:
            owner.references.append("metadata:" + ",".join(entry["metadata_columns"]))
        store.objects = {}
        chain, missing, seen = manifest, [], set()
        while chain is not None and str(chain.revision_id) not in seen:
            seen.add(str(chain.revision_id))
            missing += store.load_groups(chain.object_group_references)
            base = chain.base_revision_id
            chain = (
                next((e for e in elements if e.type == DE_REVISION_MANIFEST and e.revision_id == base), None)
                if mode != "b2" and base and not base.is_null
                else None
            )
        entry["missing_object_groups"] = missing
        try:
            root = primary_root_object(manifest)
            payload, rep = reassemble(store, root)
        except (FsshttpdError, FsshttpbDecodeError) as error:
            entry["status"] = f"incomplete: {error}"
            revisions_out.append(entry)
            continue
        zip_info = describe_zip(payload)
        status = reassembly_status(missing, rep.signature_checks, zip_info)
        entry.update(
            {
                "root_object": str(root),
                "size": rep.size,
                "sha256": hashlib.sha256(payload).hexdigest(),
                "leaf_count": rep.leaf_count,
                "signature_checks": rep.signature_checks,
                "status": status,
                "zip": zip_info,
            }
        )
        if not zip_info.get("is_zip"):
            entry["stream"] = describe_auxiliary_stream(payload)
        if out_dir is not None:
            suffix = ".docx" if zip_info.get("is_zip") else ".bin"
            target = out_dir / f"{ns_dir.name}_{mode}_rev_{manifest.revision_id.guid[:8]}_{manifest.revision_id.value}{suffix}"
            target.write_bytes(payload)
            entry["output"] = str(target)
        revisions_out.append(entry)
    report["revisions"] = revisions_out





    inferred_out: list[dict[str, Any]] = []
    if mode == "cw":
        for pile_id, pile in ordered_piles:
            pile_blobs = [
                by_id[item["blob"]]
                for item in pile["entries"].values()
                if item["blob"] in by_id and by_id[item["blob"]].status == "ok"
            ]
            pile_elements = [e for b in pile_blobs for e in b.data_elements]
            if any(e.type == DE_REVISION_MANIFEST for e in pile_elements):
                continue
            groups = [e.exguid for e in pile_elements if e.type == DE_OBJECT_GROUP]
            if not groups:
                continue
            hints = sorted({str(e.current_revision) for e in pile_elements if e.type == DE_CELL_MANIFEST})
            pile_store = ObjectStore(pile_elements)
            pile_store.load_groups(groups)
            for root in infer_root_objects(pile_store):
                item: dict[str, Any] = {
                    "source": "pile_group_set (inferred root)",
                    "pile_id": pile_id,
                    "is_current_pile": pile["is_current"],
                    "revision_id_hint": hints,
                    "root_object": str(root),
                    "object_groups": len(groups),
                }
                try:
                    payload, rep = reassemble(pile_store, root)
                except (FsshttpdError, FsshttpbDecodeError) as error:
                    item["status"] = f"incomplete: {error}"
                    inferred_out.append(item)
                    continue
                zip_info = describe_zip(payload)
                item.update(
                    {
                        "size": rep.size,
                        "sha256": hashlib.sha256(payload).hexdigest(),
                        "signature_checks": rep.signature_checks,
                        "status": reassembly_status([], rep.signature_checks, zip_info),
                        "zip": zip_info,
                    }
                )
                if out_dir is not None:
                    suffix = ".docx" if zip_info.get("is_zip") else ".bin"
                    target_path = out_dir / f"{ns_dir.name}_cw_inferred_{pile_id[:8]}_{root.guid[:8]}_{root.value}{suffix}"
                    target_path.write_bytes(payload)
                    item["output"] = str(target_path)
                inferred_out.append(item)






        manifest_revision_ids = {str(m.revision_id) for m in elements if m.type == DE_REVISION_MANIFEST}
        described: dict[str, dict[str, Any]] = {}
        for blob, hierarchy in hierarchies:
            for node in hierarchy.of_type(NODE_REVISION_MANIFEST):
                entry = described.setdefault(node.revision_id, {"variants": {}, "blobs": []})
                entry["blobs"].append(blob.name)
                variant = entry["variants"].setdefault(
                    tuple(node.references), {"roots": set(), "base": node.base_revision_id}
                )
                variant["roots"].update(node.revision_roots)
        for revision_id, entry in sorted(described.items()):
            if revision_id in manifest_revision_ids:
                continue
            for groups, variant in entry["variants"].items():
                chain = [_exguid_from_text(g) for g in groups]
                missing: list[str] = []
                base, seen = variant["base"], {revision_id}
                while base and base != NULL_EXGUID_TEXT and base not in seen:
                    seen.add(base)
                    base_manifest = next(
                        (e for e in elements if e.type == DE_REVISION_MANIFEST and str(e.revision_id) == base), None
                    )
                    if base_manifest is not None:
                        chain += base_manifest.object_group_references
                        base = str(base_manifest.base_revision_id)
                    elif base in described:
                        base_groups, base_variant = next(iter(described[base]["variants"].items()))
                        chain += [_exguid_from_text(g) for g in base_groups]
                        base = base_variant["base"]
                    else:
                        missing.append(f"base_revision:{base}")
                        break
                hierarchy_store = ObjectStore(elements)
                missing += hierarchy_store.load_groups(chain)
                primary = sorted(obj for root, obj in variant["roots"] if _namespace_of(root) == PRIMARY_STREAM_ROOT_GUID)
                if primary:
                    roots, root_source = [_exguid_from_text(primary[0])], "hierarchy_root_declaration"
                else:
                    roots, root_source = infer_root_objects(hierarchy_store), "inferred"
                for root in roots:
                    item = {
                        "source": "hierarchy_record",
                        "hierarchy_blobs": sorted(set(entry["blobs"])),
                        "pile_id": None,
                        "is_current_pile": revision_id in hierarchy_current_revisions,
                        "revision_id_hint": [revision_id],
                        "root_object": str(root),
                        "root_source": root_source,
                        "object_groups": len(groups),
                        "missing_object_groups": missing,
                    }
                    try:
                        payload, rep = reassemble(hierarchy_store, root)
                    except (FsshttpdError, FsshttpbDecodeError) as error:
                        item["status"] = f"incomplete: {error}"
                        inferred_out.append(item)
                        continue
                    zip_info = describe_zip(payload)
                    item.update(
                        {
                            "size": rep.size,
                            "sha256": hashlib.sha256(payload).hexdigest(),
                            "signature_checks": rep.signature_checks,
                            "status": reassembly_status(missing, rep.signature_checks, zip_info),
                            "zip": zip_info,
                        }
                    )
                    if out_dir is not None:
                        suffix = ".docx" if zip_info.get("is_zip") else ".bin"
                        rid = _exguid_from_text(revision_id)
                        target_path = out_dir / f"{ns_dir.name}_cw_hierarchy_{rid.guid[:8]}_{rid.value}_{root.value}{suffix}"
                        target_path.write_bytes(payload)
                        item["output"] = str(target_path)
                    inferred_out.append(item)
        report["inferred_revisions"] = inferred_out


        revision_groups: dict[str, set[str]] = {}
        for element in elements:
            if element.type == DE_REVISION_MANIFEST:
                revision_groups.setdefault(str(element.revision_id), set()).update(
                    str(g) for g in element.object_group_references
                )
        for _, hierarchy in hierarchies:
            for node in hierarchy.of_type(NODE_REVISION_MANIFEST):
                revision_groups.setdefault(node.revision_id, set()).update(node.references)
        report["revision_lineage"] = revision_lineage(revision_groups)
        described_namespaces = {_namespace_of(r) for r in revision_groups}
        orphan_namespaces = sorted(
            {e.exguid.guid for e in elements if e.type == DE_OBJECT_GROUP} - described_namespaces
        )
    else:
        orphan_namespaces = []


    claims: dict[str, dict[str, set[str]]] = {"A": {}, "B": {}, "C": {}}

    def claim(cls: str, source: str, revisions: Any) -> None:
        for revision in revisions:
            claims[cls].setdefault(revision, set()).add(source)

    claim("A", "current_pile_cell_manifest", current_revisions)
    claim("A", "current_pile_hierarchy", hierarchy_current_revisions)
    claim("A", "metadata_working_branch", working_branch)
    claim(
        "A",
        "current_pile_group_set (inferred)",
        [
            _candidate_key(i)
            for i in inferred_out
            if i.get("is_current_pile") and i["source"].startswith("pile_group_set")
            and i.get("status") in COMPLETE_STATES and i.get("zip", {}).get("is_zip")
        ],
    )
    candidates, non_document = collect_candidates(revisions_out, inferred_out)
    snapshot_list = [s for s in report.get("storage_index_snapshots", []) if "max_sequence" in s]
    if snapshot_list:
        top = max(s["max_sequence"] for s in snapshot_list)
        named = {r for s in snapshot_list if s["max_sequence"] == top for r in s.get("revisions", {})}
        claim("B", "latest_index_snapshot", named - non_document)
    lineage = report.get("revision_lineage")
    if lineage:
        known = set(candidates) | {r["revision_id"] for r in revisions_out if r.get("revision_id")}
        claim("C", "lineage_head (LIKELY)", lineage_head_claims(lineage["heads"], known, non_document))
    report["target"] = select_target(claims, candidates, lineage, orphan_namespaces)


    if mode == "cw":
        all_groups = [e.exguid for e in elements if e.type == DE_OBJECT_GROUP]
        store.objects = {}
        store.load_groups(all_groups)
        group_of_object = {}
        for group_id in all_groups:
            for object_id in store.groups[group_id].object_map():
                group_of_object.setdefault(str(object_id), str(group_id))
        revisions_of_group: dict[str, list[str]] = {}
        for manifest in [e for e in elements if e.type == DE_REVISION_MANIFEST]:
            for group_id in manifest.object_group_references:
                revisions_of_group.setdefault(str(group_id), []).append(str(manifest.revision_id))
        for _, hierarchy in hierarchies:
            for node in hierarchy.of_type(NODE_REVISION_MANIFEST):
                for group_id in node.references:
                    revisions_of_group.setdefault(group_id, []).append(node.revision_id)
        parts_out = []
        parts_dir = out_dir / f"{ns_dir.name}_cw_parts" if out_dir is not None else None
        for part in salvage_zip_parts(store):
            payload = part.pop("payload", None)
            revisions = sorted(
                {rid for obj in part.get("chunk_objects", []) for rid in revisions_of_group.get(group_of_object.get(obj, ""), [])}
            )
            part["revisions"] = revisions
            part["blobs"] = sorted(
                {element_owner[group_of_object[obj]].name for obj in part.get("chunk_objects", []) if group_of_object.get(obj) in element_owner}
            )
            if parts_dir is not None and payload is not None and part.get("name"):
                part.update(write_part(parts_dir, part["crc32"], part["name"], payload))
            parts_out.append(part)
        report["salvaged_parts"] = parts_out



        named = report["target"].get("named_revision")
        if report["target"].get("status") == "undetermined" and named:
            named_parts = [p for p in parts_out if p.get("status") == "verified" and named in p.get("revisions", [])]
            report["target"]["salvaged_parts_of_named_revision"] = [
                {k: p[k] for k in ("name", "crc32", "output") if k in p} for p in named_parts
            ]

            texts = []
            for part in named_parts:
                if part.get("name") == "word/document.xml" and part.get("output") and out_dir is not None:
                    xml = Path(part["output"]).read_text(encoding="utf-8", errors="replace")
                    text_path = out_dir / f"{ns_dir.name}_named_revision_text_{part['crc32']}.txt"
                    text_path.write_text(partial_text_report(xml, named, part["crc32"], named_parts), encoding="utf-8")
                    texts.append(str(text_path))
            if texts:
                report["target"]["salvaged_text_outputs"] = texts


    revision_reach: dict[str, str] = {}
    for manifest in [e for e in elements if e.type == DE_REVISION_MANIFEST]:
        owner = element_owner.get(str(manifest.exguid))
        refs = owner.references if owner else []
        if any(r.startswith("current:") for r in refs):
            reason = "current_revision_graph"
        elif any(r.startswith("metadata:") for r in refs):
            reason = "metadata_revision_graph"
        else:
            continue
        for group_id in manifest.object_group_references:
            group_owner = element_owner.get(str(group_id))
            if group_owner and revision_reach.get(group_owner.name) != "current_revision_graph":
                revision_reach[group_owner.name] = reason
        if owner is not None:
            revision_reach.setdefault(owner.name, reason)
    reachable_revision_ids = {
        str(m.revision_id)
        for m in elements
        if m.type == DE_REVISION_MANIFEST and element_owner.get(str(m.exguid)) is not None
        and element_owner[str(m.exguid)].name in revision_reach
    }
    for element in elements:
        if element.type == DE_CELL_MANIFEST and str(element.current_revision) in reachable_revision_ids:
            owner = element_owner.get(str(element.exguid))
            if owner:
                revision_reach.setdefault(owner.name, "metadata_revision_graph")

    report["blobs"] = []
    for blob in blobs:
        if blob.status == "ok":
            indexed = bool(blob.references or blob.name in revision_reach)
            tier = "T1" if (indexed and blob.id_matches_content) else "T2"
        elif blob.status == "no_key":
            tier = "T3"
        else:
            tier = "T5"
        if any(r.startswith("current:") for r in blob.references):
            reachability = "current_pile"
        elif blob.name in revision_reach:
            reachability = revision_reach[blob.name]
        elif blob.references:
            reachability = "older_pile_only"
        else:
            reachability = "unreferenced"
        report["blobs"].append(
            {
                "name": blob.name,
                "status": blob.status,
                "detail": blob.detail,
                "logical_size": blob.logical_size,
                "payload": blob.payload_kind,
                "data_elements": [{"type": e.type_name, "exguid": str(e.exguid)} for e in blob.data_elements],
                "references": blob.references,
                "identifier": blob.identifier,
                "identity_source": blob.identity_source,
                "id_matches_content": blob.id_matches_content,
                "native_name": blob.native_name,
                "reachability": reachability,
                "trust_tier": tier,
            }
        )
    return report


WINDOWS_DEVICE_NAMES = frozenset(
    ["CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"] + [f"{kind}{i}" for kind in ("COM", "LPT") for i in "123456789\u00b9\u00b2\u00b3"]
)
UNSAFE_NAME_CHARS = re.compile(r'[\x00-\x1f<>:"|?*]')


def safe_part_path(name: str) -> str:


    segments = []
    for raw in name.replace("\\", "/").split("/"):
        if raw in ("", ".", ".."):
            continue
        segment = UNSAFE_NAME_CHARS.sub("_", raw)
        stripped = segment.rstrip(". ")
        segment = stripped + "_" * (len(segment) - len(stripped))
        if segment.split(".", 1)[0].upper() in WINDOWS_DEVICE_NAMES:
            segment = "_" + segment
        segments.append(segment[:120])
    return "/".join(segments) or "unnamed"


def write_part(parts_dir: Path, crc32: str, name: str, payload: bytes) -> dict[str, Any]:


    relative = safe_part_path(name)
    result: dict[str, Any] = {}
    if relative != name.replace("\\", "/"):
        result["output_name"] = relative
    target = parts_dir / crc32 / relative
    folder = parts_dir.resolve()
    if folder not in target.resolve().parents:
        result["output_error"] = "the part name leads outside the part folder"
        return result
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(payload)
    except OSError as error:
        result["output_error"] = f"{type(error).__name__}: {error}"
        return result
    result["output"] = str(target)
    return result


def ensure_outside(root: Path, path: Path, what: str) -> None:


    cache = root.resolve()
    target = path.resolve()
    if target == cache or cache in target.parents:
        raise ValueError(f"{what} {path} lies inside the input cache {root}; outputs must stay out of the evidence")


def run(root: Path, key_source: str, out_dir: Path | None, mode: str = "cw") -> dict[str, Any]:
    if out_dir is not None:
        ensure_outside(root, out_dir, "--out")
    report: dict[str, Any] = {
        "tool": "cacheweave-odc-recover",
        "input_root": str(root),
        "key_source": key_source.split(":", 1)[0],
        "mode": mode,
        "boot_cluster_set_file": BOOT_CLUSTER_SET_FILE_NAME,
        "namespaces": [],
    }
    if out_dir is not None:
        out_dir.mkdir(parents=True, exist_ok=True)
    for major in sorted(p for p in root.iterdir() if p.is_dir()):
        for generation in sorted(p for p in major.iterdir() if p.is_dir()):
            for ns_dir in sorted(p for p in generation.iterdir() if p.is_dir()):
                ns_report = process_namespace(ns_dir, key_source, out_dir, mode)
                ns_report["major"] = major.name
                ns_report["generation"] = generation.name
                report["namespaces"].append(ns_report)
    return report


def main(argv: list[str] | None = None, prog: str | None = None) -> int:
    parser = argparse.ArgumentParser(prog=prog)
    parser.add_argument("root", type=Path, help="copy of the OfficeFileCache directory")
    parser.add_argument(
        "--key-source",
        default="none",
        help=(
            "none | offline:<mounted Windows volume root> | "
            "offline-files:system=<hive>,security=<hive>,masterkeys=<S-1-5-18 dir> | "
            "sessions:<file> | live (CryptUnprotectData on this machine; development only) | "
            "live-export:<new file> (as live, and writes the plaintext session list there: key material, "
            "an existing file is never overwritten)"
        ),
    )
    parser.add_argument("--mode", choices=MODES, default="cw", help="recovery strategy")
    parser.add_argument("--out", type=Path, help="directory for reassembled files and salvaged parts")
    parser.add_argument("--report", type=Path, help="write the JSON report here")
    args = parser.parse_args(argv)
    try:
        if args.report:
            ensure_outside(args.root, args.report, "--report")
        if args.out is not None:
            ensure_outside(args.root, args.out, "--out")
    except ValueError as error:
        parser.error(str(error))
    report = run(args.root, args.key_source, args.out, args.mode)
    text = json.dumps(report, indent=2, default=str)
    if args.report:
        args.report.write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
