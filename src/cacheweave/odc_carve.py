


from __future__ import annotations

import argparse
import dataclasses
import hashlib
import json
import os
import re
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any





os.environ.setdefault("OPENBLAS_NUM_THREADS", "1")

import numpy as np

from .formats.arx_codec import (
    ARX_SUPERBLOCK_ROOT_LENGTH,
    ZIGZAG_ALLOCATOR_ROOT,
    ArxDecodeError,
    _extract_storage_frame_prefix,
    decode_nextgen_allocator,
    decode_physical_volume_superblocks,
    encode_syzygy_identifier,
    extract_volume_files,
)
from .formats.csi_blobheap import (
    NODE_REVISION_MANIFEST,
    ROOT_BLOB_SIGNATURE,
    BlobHeapDecodeError,
    parse_hierarchy_record,
    root_blob_size,
)
from .formats.fsshttpb import (
    BLOBHEAP_MAGIC,
    DE_REVISION_MANIFEST,
    SO_DATA_ELEMENT,
    FsshttpbDecodeError,
    Reader,
    parse_blobheap_record,
    parse_data_element,
)
from .odc_recover import BLOCK_SIZE, SessionKey, classify, decrypt_blob, load_sessions, metadata_exguid_references
from .crypto.spookyhash import cluster_id_from_label, hash128_bytes
from .odc.syzygy_cluster_set import (
    BOOT_CLUSTER_SET_FILE_NAME,
    LABEL_BY_ID,
    ClusterRecord,
    ClusterSetDecodeError,
    parse_cluster_record,
)
from .crypto.syzygy_protected_stream import (
    FOOTER_SIZE,
    MAX_ENCRYPTED_SHARD_SIZE,
    ProtectedStreamDecodeError,
    ProtectedStreamFooter,
    ProtectedStreamShard,
    decode_protected_footer,
    decrypt_shard_unauthenticated,
    inspect_protected_stream,
    verify_shard_hmac,
)
from .formats.terse_codec import TerseDecodeError, decode_document_metadata, decode_envelope

CLUSTER_SIZE = 0x1000
SECTOR_SIZE = 0x200
RECORD_WINDOW = 0x100000
VAULT_ID = cluster_id_from_label("_vault")
METADATA_ID = cluster_id_from_label("DocumentMetadata")
FOOTER_PAYLOAD_RANGE = (84, FOOTER_SIZE - 9)






SCAN_CHUNK = 64 * 1024 * 1024
MFT_RECORD_STEP = 0x400


class FileImage:


    def __init__(self, path: Path) -> None:
        self._handle = open(path, "rb")
        self._size = self._handle.seek(0, 2)

    def __len__(self) -> int:
        return self._size

    def __getitem__(self, key: Any) -> Any:
        if isinstance(key, slice):
            start, stop, step = key.indices(self._size)
            if step != 1:
                raise ValueError("FileImage supports contiguous slices only")
            self._handle.seek(start)
            return self._handle.read(max(0, stop - start))
        self._handle.seek(key)
        return self._handle.read(1)[0]

    def chunks(self, size: int, overlap: int):
        for start in range(0, self._size, size):
            self._handle.seek(start)
            yield start, self._handle.read(size + overlap)

    def close(self) -> None:
        self._handle.close()

    def __enter__(self) -> "FileImage":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()


def _chunks(image: Any, overlap: int):


    if isinstance(image, FileImage):
        for start, block in image.chunks(SCAN_CHUNK, overlap):
            yield start, np.frombuffer(block, dtype=np.uint8)
        return
    data = np.frombuffer(image, dtype=np.uint8)
    for start in range(0, len(data), SCAN_CHUNK):
        yield start, data[start : start + SCAN_CHUNK + overlap]


def aligned_offsets(image: Any, value: int, step: int) -> list[int]:


    found: list[int] = []
    for start, view in _chunks(image, 0):
        found.extend(start + int(i) * step for i in np.flatnonzero(view[::step] == value))
    return found


def footer_candidates(image: Any) -> list[int]:


    total = len(image)
    found: list[int] = []
    for start, view in _chunks(image, 16):
        if len(view) < 10:
            break

        index = np.flatnonzero(view[:-9] == 0x02)
        if not index.size:
            continue
        size = view[index + 5]
        keep = (view[index + 9] == 0x01) & (view[index + 6] == 0) & (view[index + 7] == 0) & (view[index + 8] == 0)
        keep &= (size >= FOOTER_PAYLOAD_RANGE[0]) & (size <= FOOTER_PAYLOAD_RANGE[1])
        for relative in index[keep]:
            offset = start + int(relative)
            if offset < start + SCAN_CHUNK and offset + FOOTER_SIZE <= total:
                found.append(offset)
    return found


def ntfs_fixed_record(record: bytes) -> bytes | None:


    if len(record) < 0x200 or record[:4] != b"FILE":
        return None
    usa_offset, usa_count = struct.unpack_from("<HH", record, 4)
    size = struct.unpack_from("<I", record, 28)[0]
    if size not in (0x400, 0x1000) or len(record) < size or usa_count != size // 0x200 + 1:
        return None
    if not 0x28 <= usa_offset <= 0x100 - 2 * usa_count:
        return None
    usn = record[usa_offset : usa_offset + 2]
    fixed = bytearray(record[:size])
    for sector in range(1, usa_count):
        end = sector * 0x200
        if fixed[end - 2 : end] != usn:
            return None
        fixed[end - 2 : end] = record[usa_offset + 2 * sector : usa_offset + 2 * sector + 2]
    return bytes(fixed)


@dataclass
class Candidates:


    records: list[int]
    mft: list[int]
    footers: list[int]
    arx: list[int] = field(default_factory=list)


def scan_candidates(image: Any) -> Candidates:


    total = len(image)
    found = Candidates([], [], [])
    for start, view in _chunks(image, 16):
        core = view[:SCAN_CHUNK]
        found.records.extend(start + int(i) * SECTOR_SIZE for i in np.flatnonzero(core[::SECTOR_SIZE] == 0x75))
        found.mft.extend(start + int(i) * MFT_RECORD_STEP for i in np.flatnonzero(core[::MFT_RECORD_STEP] == 0x46))
        found.arx.extend(start + int(i) * CLUSTER_SIZE for i in np.flatnonzero(core[::CLUSTER_SIZE] == 0x69))
        if len(view) < 10:
            continue
        index = np.flatnonzero(view[:-9] == 0x02)
        if not index.size:
            continue
        size = view[index + 5]
        keep = (view[index + 9] == 0x01) & (view[index + 6] == 0) & (view[index + 7] == 0) & (view[index + 8] == 0)
        keep &= (size >= FOOTER_PAYLOAD_RANGE[0]) & (size <= FOOTER_PAYLOAD_RANGE[1])
        for relative in index[keep]:
            offset = start + int(relative)
            if offset < start + SCAN_CHUNK and offset + FOOTER_SIZE <= total:
                found.footers.append(offset)
    return found


def mft_records(image: Any, offsets: list[int] | None = None) -> list[tuple[int, bytes]]:


    records = []
    for offset in aligned_offsets(image, ord("F"), MFT_RECORD_STEP) if offsets is None else offsets:
        fixed = ntfs_fixed_record(bytes(image[offset : offset + 0x1000]))
        if fixed is not None:
            records.append((offset, fixed))
    return records


def mft_scan(image: Any, offsets: list[int]) -> tuple[list[tuple[int, int]], list[tuple[int, bytes, list]]]:


    ranges: list[tuple[int, int]] = []
    resident: list[tuple[int, bytes, list]] = []
    for offset in offsets:
        fixed = ntfs_fixed_record(bytes(image[offset : offset + 0x1000]))
        if fixed is None:
            continue
        ranges.append((offset, offset + len(fixed)))
        if b"\x02" in fixed:
            footers = carve_footers(fixed)
            if footers:
                resident.append((offset, fixed, footers))
    return ranges, resident


def carve_cluster_records(image: Any, step: int = SECTOR_SIZE, offsets: list[int] | None = None) -> list[ClusterRecord]:


    records, seen = [], set()
    for offset in aligned_offsets(image, 0x75, step) if offsets is None else offsets:

        head = bytes(image[offset : offset + 10])
        if len(head) < 10 or head[1] != 0x02 or struct.unpack_from("<I", head, 6)[0] > RECORD_WINDOW:
            continue
        window = 1 + 9 + struct.unpack_from("<I", head, 6)[0]
        window = -(-window // CLUSTER_SIZE) * CLUSTER_SIZE
        try:
            record = parse_cluster_record(image[offset : offset + window], 0, CLUSTER_SIZE)
        except ClusterSetDecodeError:
            continue
        key = (record.cluster_id, record.generation, hashlib.sha256(record.value).digest())
        if key not in seen:
            seen.add(key)
            records.append(dataclasses.replace(record, offset=offset))
    return records


@dataclass(frozen=True)
class CarvedFooter:
    offset: int
    footer: ProtectedStreamFooter


def _excluder(exclude: list[tuple[int, int]]):


    ends = {start: end for start, end in exclude}
    if not ends:
        return lambda position: False

    def inside(position: int) -> bool:
        base = position - position % MFT_RECORD_STEP
        return any(ends.get(base - k * MFT_RECORD_STEP, -1) > position for k in range(4))

    return inside


def carve_footers(
    image: Any, exclude: list[tuple[int, int]] = (), candidates: list[int] | None = None
) -> list[CarvedFooter]:


    found = []
    inside = _excluder(list(exclude))
    for position in footer_candidates(image) if candidates is None else candidates:
        if inside(position):
            continue
        try:
            found.append(CarvedFooter(position, decode_protected_footer(bytes(image[position : position + FOOTER_SIZE]))))
        except ProtectedStreamDecodeError:
            pass
    return found






def structural_length(plaintext: bytes) -> int | None:


    if plaintext[:4] == struct.pack("<I", BLOBHEAP_MAGIC) and len(plaintext) > 5:
        reader, end = Reader(plaintext, 5), 5
        while reader.remaining >= 2:
            peek = reader.peek(2)
            if peek[0] & 0x03 or (int.from_bytes(peek, "little") >> 3) & 0x3F != SO_DATA_ELEMENT:
                break
            try:
                parse_data_element(reader)
            except FsshttpbDecodeError:
                break
            end = reader.pos
        return end if end > 5 else None
    if plaintext[:1] == b"\x02" and len(plaintext) >= 9:
        try:
            return 9 + decode_envelope(plaintext, allow_trailing=True).payload_size
        except TerseDecodeError:
            return None
    if plaintext[:16] == ROOT_BLOB_SIGNATURE:
        try:
            return root_blob_size(plaintext)
        except BlobHeapDecodeError:
            return None
    return None


def _shard(index: int, footer: ProtectedStreamFooter, size: int) -> ProtectedStreamShard:
    return ProtectedStreamShard(index, 0, size, size, 0, size, 0, "", footer)


def _alignment(offset: int) -> str:
    if offset % CLUSTER_SIZE == 0:
        return "cluster"
    return "sector" if offset % SECTOR_SIZE == 0 else "block"


def start_candidates(footer_offset: int, floor: int = 0) -> list[int]:


    lowest = max(floor, footer_offset - MAX_ENCRYPTED_SHARD_SIZE)
    starts = range(footer_offset - BLOCK_SIZE, lowest - 1, -BLOCK_SIZE)
    return sorted(starts, key=lambda s: (s % CLUSTER_SIZE != 0, s % SECTOR_SIZE != 0, footer_offset - s))


@dataclass
class CarvedStream:
    start: int
    end: int
    session_id: int
    shard_offsets: list[int]
    start_alignment: str
    attempts: int
    logical_size: int | None = None
    name: str | None = None
    status: str = "ok"
    data: bytes = field(default=b"", repr=False)
    plaintext: bytes = field(default=b"", repr=False)

    def to_json_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "status": self.status,
            "start": self.start,
            "end": self.end,
            "shards": len(self.shard_offsets),
            "session_id": self.session_id,
            "start_alignment": self.start_alignment,
            "hmac_attempts": self.attempts,
            "logical_size": self.logical_size,
        }


def rebuild_streams(
    image: bytes, footers: list[CarvedFooter], keys: dict[int, SessionKey]
) -> tuple[list[CarvedStream], list[dict[str, Any]]]:


    by_offset = {f.offset: f for f in footers}
    consumed: set[int] = set()
    streams: list[CarvedStream] = []
    unverified: list[dict[str, Any]] = []
    for carved in sorted(footers, key=lambda f: f.offset):
        if carved.offset in consumed:
            continue
        key = keys.get(carved.footer.session_id)
        if key is None:
            unverified.append({"footer": carved.offset, "reason": f"no key for session {carved.footer.session_id}"})
            continue
        attempts, start = 0, None
        for candidate in start_candidates(carved.offset):
            attempts += 1
            size = carved.offset - candidate
            if verify_shard_hmac(_shard(0, carved.footer, size), image[candidate : carved.offset], key.stream_key, key.stream_salt):
                start = candidate
                break
        if start is None:
            unverified.append({"footer": carved.offset, "reason": "no start verifies as shard 0", "attempts": attempts})
            continue
        shards = [(start, carved)]
        consumed.add(carved.offset)

        while shards[-1][1].offset - shards[-1][0] == MAX_ENCRYPTED_SHARD_SIZE:
            next_start = shards[-1][1].offset + FOOTER_SIZE
            follower = next(
                (
                    by_offset[o]
                    for o in range(next_start + BLOCK_SIZE, next_start + MAX_ENCRYPTED_SHARD_SIZE + 1, BLOCK_SIZE)
                    if o in by_offset and o not in consumed
                    and by_offset[o].footer.session_id == carved.footer.session_id
                    and verify_shard_hmac(
                        _shard(len(shards), by_offset[o].footer, o - next_start),
                        image[next_start:o], key.stream_key, key.stream_salt,
                    )
                ),
                None,
            )
            if follower is None:
                break
            shards.append((next_start, follower))
            consumed.add(follower.offset)
        plaintext = b"".join(
            decrypt_shard_unauthenticated(
                _shard(index, footer.footer, footer.offset - shard_start),
                image[shard_start : footer.offset], key.stream_key, key.stream_salt,
            )
            for index, (shard_start, footer) in enumerate(shards)
        )
        stream = CarvedStream(
            start=start,
            end=shards[-1][1].offset + FOOTER_SIZE,
            session_id=carved.footer.session_id,
            shard_offsets=[s for s, _ in shards],
            start_alignment=_alignment(start),
            attempts=attempts,
        )
        logical = structural_length(plaintext)
        padding = len(plaintext) - logical if logical is not None else None
        if padding is None or not 0 <= padding < BLOCK_SIZE:
            stream.status = "length_unresolved"
            streams.append(stream)
            continue
        data = image[start : stream.end + padding]
        status, detail, verified = decrypt_blob(data, keys)
        if status != "ok" or verified != plaintext[:logical]:
            stream.status = f"rebuild_failed: {status} {detail}"
            streams.append(stream)
            continue
        stream.end += padding
        stream.logical_size = logical
        stream.data, stream.plaintext = data, verified
        stream.name = f"e_{encode_syzygy_identifier(hash128_bytes(verified))}.R"
        streams.append(stream)
    return streams, unverified






ARX_SUPERBLOCK_HEAD = b"\x69\x04\x22\x4d\x18"


@dataclass
class CarvedArxVolume:
    offset: int
    size: int
    files: list = field(default_factory=list, repr=False)
    summary: dict[str, Any] = field(default_factory=dict)
    error: str | None = None

    def session_ids(self) -> list[int]:

        found = []
        for item in self.files:
            if classify(item.data) != "protected_stream":
                continue
            try:
                found.append(inspect_protected_stream(item.data, BLOCK_SIZE).shards[0].footer.session_id)
            except (ProtectedStreamDecodeError, ValueError, IndexError):
                continue
        return found

    def to_json_dict(self) -> dict[str, Any]:
        return {"offset": self.offset, "size": self.size, "files": len(self.files), "error": self.error,
                "file_index_generation": self.summary.get("file_index_generation")}


def carve_arx_volumes(image: Any, offsets: list[int]) -> list[CarvedArxVolume]:


    volumes: list[CarvedArxVolume] = []
    covered = -1
    for offset in sorted(offsets):
        if offset < covered or image[offset : offset + len(ARX_SUPERBLOCK_HEAD)] != ARX_SUPERBLOCK_HEAD:
            continue
        try:
            decode_physical_volume_superblocks(image[offset : offset + ARX_SUPERBLOCK_ROOT_LENGTH], volume_size=len(image) - offset)
        except ArxDecodeError:
            continue
        states = []
        half_size = ZIGZAG_ALLOCATOR_ROOT.length // 2
        for half in (ZIGZAG_ALLOCATOR_ROOT.offset, ZIGZAG_ALLOCATOR_ROOT.offset + half_size):
            raw = image[offset + half : offset + half + half_size]
            try:
                states.append(decode_nextgen_allocator(_extract_storage_frame_prefix(raw, max_decoded_size=16 << 20, context="allocator half")))
            except ArxDecodeError:
                continue
        if not states:
            volumes.append(CarvedArxVolume(offset, 0, error="Superblock pair without a readable allocator state"))
            covered = offset + ARX_SUPERBLOCK_ROOT_LENGTH
            continue
        size = max(states, key=lambda state: state.generation).physical_volume_size
        if size <= ARX_SUPERBLOCK_ROOT_LENGTH or size % CLUSTER_SIZE or offset + size > len(image):
            volumes.append(CarvedArxVolume(offset, size, error="allocator volume size does not fit the image"))
            covered = offset + ARX_SUPERBLOCK_ROOT_LENGTH
            continue
        try:
            files, summary = extract_volume_files(image[offset : offset + size], include_stale=True)
        except ArxDecodeError as error:
            volumes.append(CarvedArxVolume(offset, size, error=str(error)))
            covered = offset + ARX_SUPERBLOCK_ROOT_LENGTH
            continue
        volumes.append(CarvedArxVolume(offset, size, list(files), summary))
        covered = offset + size
    return volumes






def _revision_ids(plaintexts: list[bytes]) -> set[str]:
    revisions: set[str] = set()
    for plaintext in plaintexts:
        if plaintext[:4] == struct.pack("<I", BLOBHEAP_MAGIC):
            try:
                revisions |= {
                    str(e.revision_id) for e in parse_blobheap_record(plaintext).elements if e.type == DE_REVISION_MANIFEST
                }
            except FsshttpbDecodeError:
                pass
        elif plaintext[:1] == b"\x02":
            try:
                revisions |= {n.revision_id for n in parse_hierarchy_record(plaintext).of_type(NODE_REVISION_MANIFEST)}
            except BlobHeapDecodeError:
                pass
    return revisions


def _metadata_revisions(record: ClusterRecord) -> set[str]:
    try:
        metadata = decode_document_metadata(record.value)
    except (TerseDecodeError, ValueError):
        return set()
    return {ref["exguid"] for ref in metadata_exguid_references(metadata.elements)}


def _rebuild_resident(
    resident: list[tuple[int, bytes, list[CarvedFooter]]], session_ids: set[int], keys: dict[int, SessionKey]
) -> tuple[list[CarvedStream], list[dict[str, Any]]]:


    streams: list[CarvedStream] = []
    unverified: list[dict[str, Any]] = []
    for record_offset, record, record_footers in resident:
        own = [f for f in record_footers if f.footer.session_id in session_ids]
        if not own:
            continue
        found, failed = rebuild_streams(record, own, keys)
        for stream in found:
            stream.start += record_offset
            stream.end += record_offset
            stream.shard_offsets = [o + record_offset for o in stream.shard_offsets]
            stream.start_alignment = "mft_resident"
        for item in failed:
            item["footer"] += record_offset
            item["mft_record"] = record_offset
        streams += found
        unverified += failed
    return streams, unverified


def carve(image: Any, key_source: str, out_root: Path | None) -> dict[str, Any]:


    scan = scan_candidates(image)
    records = carve_cluster_records(image, offsets=scan.records)
    mft, resident = mft_scan(image, scan.mft)
    footers = carve_footers(image, mft, candidates=scan.footers)
    report: dict[str, Any] = {
        "tool": "cacheweave-odc-carve",
        "image_size": len(image),
        "cluster_records": [
            {"offset": r.offset, "label": LABEL_BY_ID.get(r.cluster_id, f"0x{r.cluster_id:016x}"), "generation": r.generation}
            for r in records
        ],
        "footers": len(footers),
        "mft_records": len(mft),
        "mft_resident_footers": sum(len(found) for _, _, found in resident),
        "namespaces": [],
    }
    vaults: dict[bytes, list[ClusterRecord]] = {}
    for record in records:
        if record.cluster_id == VAULT_ID:
            vaults.setdefault(record.value, []).append(record)
    metadata_records = [r for r in records if r.cluster_id == METADATA_ID]
    all_streams: list[CarvedStream] = []
    all_unverified: list[dict[str, Any]] = []
    known_sessions: set[int] = set()
    assembled: list[tuple[dict[str, Any], set[int], Path | None]] = []
    for index, (vault_value, vault_records) in enumerate(vaults.items()):
        namespace: dict[str, Any] = {"namespace": f"CARVED{index}", "vault_generations": [r.generation for r in vault_records]}
        keys = load_sessions(vault_value, key_source, namespace)
        session_ids = set(keys)
        known_sessions |= session_ids
        streams, unverified = rebuild_streams(image, [f for f in footers if f.footer.session_id in session_ids], keys)
        resident_streams, resident_unverified = _rebuild_resident(resident, session_ids, keys)
        streams += resident_streams
        unverified += resident_unverified
        all_streams += streams
        all_unverified += unverified
        good = [s for s in streams if s.status == "ok"]
        revisions = _revision_ids([s.plaintext for s in good])
        metadata = [r for r in metadata_records if _metadata_revisions(r) & revisions]
        namespace.update(
            {
                "streams": [s.to_json_dict() for s in streams],
                "metadata_generations": sorted(r.generation for r in metadata),
                "revisions_seen": sorted(revisions),
            }
        )
        if out_root is not None:
            ns_dir = out_root / "0" / "0" / namespace["namespace"]
            ns_dir.mkdir(parents=True, exist_ok=False)
            cluster_bytes = b"".join(
                image[r.offset : r.offset + r.cluster_count * CLUSTER_SIZE]
                for r in sorted(vault_records + metadata, key=lambda r: r.offset)
            )
            (ns_dir / BOOT_CLUSTER_SET_FILE_NAME).write_bytes(cluster_bytes)
            for stream in good:
                (ns_dir / stream.name).write_bytes(stream.data)
        report["namespaces"].append(namespace)
        assembled.append((namespace, session_ids, out_root / "0" / "0" / namespace["namespace"] if out_root is not None else None))
    report["arx_volumes_unassigned"] = _place_arx_volumes(carve_arx_volumes(image, scan.arx), assembled)
    every_footer = footers + [CarvedFooter(offset + f.offset, f.footer) for offset, _, found in resident for f in found]
    report["unverified_footers"] = all_unverified + [
        {"footer": f.offset, "reason": f"session {f.footer.session_id} is in no carved vault (or no key)"}
        for f in every_footer
        if f.footer.session_id not in known_sessions
    ]
    report["summary"] = {
        "vaults": len(vaults),
        "streams_rebuilt": sum(1 for s in all_streams if s.status == "ok"),
        "streams_by_alignment": {
            a: sum(1 for s in all_streams if s.status == "ok" and s.start_alignment == a)
            for a in ("cluster", "sector", "block", "mft_resident")
        },
        "unverified_footers": len(report["unverified_footers"]),
        "arx_volumes": sum(len(ns.get("arx_volumes", [])) for ns in report["namespaces"]),
        "arx_files": sum(v.get("files", 0) for ns in report["namespaces"] for v in ns.get("arx_volumes", [])),
    }
    return report


SAFE_NAME = re.compile(r"[A-Za-z0-9_.\-]{1,200}")


def _place_arx_volumes(
    volumes: list[CarvedArxVolume], assembled: list[tuple[dict[str, Any], set[int], Path | None]]
) -> list[dict[str, Any]]:


    unassigned: list[dict[str, Any]] = []
    for volume in volumes:
        entry = volume.to_json_dict()
        if volume.error or not volume.files:
            unassigned.append(entry)
            continue
        sessions = volume.session_ids()
        best = None
        for namespace, ids, ns_dir in assembled:
            hits = sum(1 for session in sessions if session in ids)
            if hits and (best is None or hits > best[0]):
                best = (hits, namespace, ns_dir)
        if best is None:
            entry["reason"] = "no carved vault holds its crypt sessions"
            unassigned.append(entry)
            continue
        _, namespace, ns_dir = best
        written, refused = 0, []
        if ns_dir is not None:
            for item in volume.files:
                if not SAFE_NAME.fullmatch(item.name) or item.name in (".", ".."):
                    refused.append(item.name[:80])
                    continue
                target = ns_dir / item.name
                if not target.exists():
                    target.write_bytes(item.data)
                    written += 1
        entry.update({"written": written, "refused_names": refused})
        namespace.setdefault("arx_volumes", []).append(entry)
    return unassigned


def main(argv: list[str] | None = None, prog: str | None = None) -> int:
    parser = argparse.ArgumentParser(prog=prog)
    parser.add_argument("image", type=Path, help="raw image or unallocated-space extract (read-only)")
    parser.add_argument("--key-source", required=True, help="key provider, usually offline:<Windows root>")
    parser.add_argument("--out", type=Path, required=True, help="new directory for the carved cache tree")
    parser.add_argument("--report", type=Path)
    args = parser.parse_args(argv)
    if args.out.exists():
        parser.error("--out must not exist")
    with open(args.image, "rb") as handle:
        if handle.read(8) == b"vhdxfile":
            parser.error("dynamic VHDX: convert to a raw or fixed VHD first (Convert-VHD -VHDType Fixed)")

    with FileImage(args.image) as image:
        report = carve(image, args.key_source, args.out / "OfficeFileCache")
    text = json.dumps(report, indent=2)
    if args.report:
        args.report.write_text(text, encoding="utf-8")
    print(json.dumps(report["summary"], indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
