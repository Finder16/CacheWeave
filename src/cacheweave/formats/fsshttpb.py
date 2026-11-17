

from __future__ import annotations

import struct
import uuid
from dataclasses import dataclass, field
from typing import Any

BLOBHEAP_MAGIC = 0x4969AACF
BLOBHEAP_HEADER_SIZE = 5


SO_DATA_ELEMENT = 0x01
SO_OBJECT_DATA_BLOB = 0x02
SO_OBJECT_EXCLUDED_DATA = 0x03
SO_OBJECT_DATA_BLOB_DECLARATION = 0x05
SO_DATA_ELEMENT_HASH = 0x06
SO_STORAGE_MANIFEST_ROOT_DECLARE = 0x07
SO_REVISION_MANIFEST_ROOT_DECLARE = 0x0A
SO_CELL_MANIFEST_CURRENT_REVISION = 0x0B
SO_STORAGE_MANIFEST_SCHEMA_GUID = 0x0C
SO_STORAGE_INDEX_REVISION_MAPPING = 0x0D
SO_STORAGE_INDEX_CELL_MAPPING = 0x0E
SO_STORAGE_INDEX_MANIFEST_MAPPING = 0x11
SO_OBJECT_DATA = 0x16
SO_OBJECT_DECLARATION = 0x18
SO_REVISION_MANIFEST_OBJECT_GROUP_REFERENCES = 0x19
SO_REVISION_MANIFEST = 0x1A
SO_OBJECT_DATA_BLOB_REFERENCE = 0x1C
SO_OBJECT_GROUP_DECLARATIONS = 0x1D
SO_OBJECT_GROUP_DATA = 0x1E
SO_DATA_ELEMENT_FRAGMENT = 0x6A
SO_OBJECT_GROUP_METADATA = 0x78
SO_OBJECT_GROUP_METADATA_DECLARATIONS = 0x79


DE_STORAGE_INDEX = 0x01
DE_STORAGE_MANIFEST = 0x02
DE_CELL_MANIFEST = 0x03
DE_REVISION_MANIFEST = 0x04
DE_OBJECT_GROUP = 0x05
DE_DATA_ELEMENT_FRAGMENT = 0x06
DE_OBJECT_DATA_BLOB = 0x0A

DATA_ELEMENT_TYPE_NAMES = {
    DE_STORAGE_INDEX: "storage_index",
    DE_STORAGE_MANIFEST: "storage_manifest",
    DE_CELL_MANIFEST: "cell_manifest",
    DE_REVISION_MANIFEST: "revision_manifest",
    DE_OBJECT_GROUP: "object_group",
    DE_DATA_ELEMENT_FRAGMENT: "data_element_fragment",
    DE_OBJECT_DATA_BLOB: "object_data_blob",
}


class FsshttpbDecodeError(ValueError):
    pass


@dataclass(frozen=True, order=True)
class ExGuid:


    guid: str
    value: int

    @property
    def is_null(self) -> bool:
        return self.value == 0 and self.guid == "00000000-0000-0000-0000-000000000000"

    def __str__(self) -> str:
        return f"{{{self.guid}}},{self.value}"


NULL_EXGUID = ExGuid("00000000-0000-0000-0000-000000000000", 0)


@dataclass(frozen=True)
class SerialNumber:
    guid: str
    value: int


@dataclass(frozen=True)
class CellId:
    first: ExGuid
    second: ExGuid


@dataclass(frozen=True)
class StreamHeader:
    kind: str
    type: int
    compound: bool
    length: int
    size: int


class Reader:
    def __init__(self, data: bytes, offset: int = 0, end: int | None = None) -> None:
        self.data = bytes(data)
        self.pos = offset
        self.end = len(self.data) if end is None else end

    @property
    def remaining(self) -> int:
        return self.end - self.pos

    def take(self, count: int) -> bytes:
        if count < 0 or self.pos + count > self.end:
            raise FsshttpbDecodeError(
                f"need {count} bytes at 0x{self.pos:x}, only {self.remaining} remain"
            )
        value = self.data[self.pos : self.pos + count]
        self.pos += count
        return value

    def peek(self, count: int = 1) -> bytes:
        return self.data[self.pos : min(self.pos + count, self.end)]

    def u8(self) -> int:
        return self.take(1)[0]

    def u16(self) -> int:
        return struct.unpack("<H", self.take(2))[0]

    def u32(self) -> int:
        return struct.unpack("<I", self.take(4))[0]

    def u64(self) -> int:
        return struct.unpack("<Q", self.take(8))[0]

    def guid(self) -> str:
        return str(uuid.UUID(bytes_le=self.take(16)))


    def compact_u64(self) -> int:
        first = self.peek(1)
        if not first:
            raise FsshttpbDecodeError("truncated compact uint64")
        b = first[0]
        if b == 0:
            self.pos += 1
            return 0
        if b & 0x01:
            self.pos += 1
            return b >> 1
        if b & 0x02:
            return int.from_bytes(self.take(2), "little") >> 2
        if b & 0x04:
            return int.from_bytes(self.take(3), "little") >> 3
        if b & 0x08:
            return int.from_bytes(self.take(4), "little") >> 4
        if b & 0x10:
            return int.from_bytes(self.take(5), "little") >> 5
        if b & 0x20:
            return int.from_bytes(self.take(6), "little") >> 6
        if b & 0x40:
            return int.from_bytes(self.take(7), "little") >> 7
        if b == 0x80:
            self.pos += 1
            return self.u64()
        raise FsshttpbDecodeError(f"invalid compact uint64 prefix 0x{b:02x}")


    def exguid(self) -> ExGuid:
        first = self.peek(1)
        if not first:
            raise FsshttpbDecodeError("truncated extended GUID")
        b = first[0]
        if b == 0:
            self.pos += 1
            return NULL_EXGUID
        if b & 0x07 == 0x04:
            self.pos += 1
            return ExGuid(self.guid(), b >> 3)
        if b & 0x3F == 0x20:
            value = self.u16() >> 6
            return ExGuid(self.guid(), value)
        if b & 0x7F == 0x40:
            value = int.from_bytes(self.take(3), "little") >> 7
            return ExGuid(self.guid(), value)
        if b == 0x80:
            self.pos += 1
            value = self.u32()
            return ExGuid(self.guid(), value)
        raise FsshttpbDecodeError(f"invalid extended GUID prefix 0x{b:02x} at 0x{self.pos:x}")

    def exguid_array(self) -> tuple[ExGuid, ...]:
        count = self.compact_u64()
        return tuple(self.exguid() for _ in range(count))


    def serial(self) -> SerialNumber | None:
        b = self.u8()
        if b == 0:
            return None
        if b != 0x80:
            raise FsshttpbDecodeError(f"invalid serial number prefix 0x{b:02x}")
        return SerialNumber(self.guid(), self.u64())

    def cell_id(self) -> CellId:
        return CellId(self.exguid(), self.exguid())

    def cell_id_array(self) -> tuple[CellId, ...]:
        count = self.compact_u64()
        return tuple(self.cell_id() for _ in range(count))


    def binary_item(self) -> bytes:
        return self.take(self.compact_u64())


    def header(self) -> StreamHeader:
        first = self.peek(1)
        if not first:
            raise FsshttpbDecodeError("truncated stream object header")
        kind = first[0] & 0x03
        start = self.pos
        if kind == 0x0:
            value = self.u16()
            return StreamHeader(
                "start16", (value >> 3) & 0x3F, bool(value & 0x04), value >> 9, 2
            )
        if kind == 0x2:
            value = self.u32()
            length = value >> 17
            if length == 0x7FFF:
                length = self.compact_u64()
            return StreamHeader(
                "start32",
                (value >> 3) & 0x3FFF,
                bool(value & 0x04),
                length,
                self.pos - start,
            )
        if kind == 0x1:
            value = self.u8()
            return StreamHeader("end8", value >> 2, False, 0, 1)
        value = self.u16()
        return StreamHeader("end16", value >> 2, False, 0, 2)

    def expect_start(self, so_type: int) -> StreamHeader:
        header = self.header()
        if header.kind not in ("start16", "start32") or header.type != so_type:
            raise FsshttpbDecodeError(
                f"expected start of stream object 0x{so_type:x}, got {header.kind} "
                f"0x{header.type:x} at 0x{self.pos - header.size:x}"
            )
        return header

    def expect_end(self, so_type: int) -> StreamHeader:
        header = self.header()
        if header.kind not in ("end8", "end16") or header.type != so_type:
            raise FsshttpbDecodeError(
                f"expected end of stream object 0x{so_type:x}, got {header.kind} "
                f"0x{header.type:x} at 0x{self.pos - header.size:x}"
            )
        return header

    def peek_header(self) -> StreamHeader:
        saved = self.pos
        try:
            return self.header()
        finally:
            self.pos = saved


@dataclass
class ObjectDeclaration:
    exguid: ExGuid
    partition_id: int
    data_size: int | None
    object_references_count: int
    cell_references_count: int
    blob_exguid: ExGuid | None = None


@dataclass
class ObjectData:
    kind: str
    object_references: tuple[ExGuid, ...]
    cell_references: tuple[CellId, ...]
    data: bytes | None = None
    excluded_size: int | None = None
    blob_exguid: ExGuid | None = None


@dataclass
class DataElement:
    exguid: ExGuid
    serial: SerialNumber | None
    type: int
    offset: int
    size: int

    manifest_mappings: list[tuple[ExGuid, SerialNumber | None]] = field(default_factory=list)
    cell_mappings: list[tuple[CellId, ExGuid, SerialNumber | None]] = field(default_factory=list)
    revision_mappings: list[tuple[ExGuid, ExGuid, SerialNumber | None]] = field(default_factory=list)

    schema_guid: str | None = None
    storage_roots: list[tuple[ExGuid, CellId]] = field(default_factory=list)

    current_revision: ExGuid | None = None

    revision_id: ExGuid | None = None
    base_revision_id: ExGuid | None = None
    revision_roots: list[tuple[ExGuid, ExGuid]] = field(default_factory=list)
    object_group_references: list[ExGuid] = field(default_factory=list)

    data_element_hash: tuple[int, bytes] | None = None
    declarations: list[ObjectDeclaration] = field(default_factory=list)
    metadata: list[int] = field(default_factory=list)
    objects: list[ObjectData] = field(default_factory=list)

    fragment: dict[str, Any] | None = None
    blob_data: bytes | None = None

    @property
    def type_name(self) -> str:
        return DATA_ELEMENT_TYPE_NAMES.get(self.type, f"unknown_0x{self.type:x}")

    def object_map(self) -> dict[ExGuid, tuple[ObjectDeclaration, ObjectData]]:


        if len(self.declarations) != len(self.objects):
            raise FsshttpbDecodeError(
                f"object group has {len(self.declarations)} declarations but "
                f"{len(self.objects)} data entries"
            )
        return {
            declaration.exguid: (declaration, data)
            for declaration, data in zip(self.declarations, self.objects)
        }


def _parse_object_group(reader: Reader, element: DataElement) -> None:
    header = reader.peek_header()
    if header.kind.startswith("start") and header.type == SO_DATA_ELEMENT_HASH:
        reader.header()
        scheme = reader.compact_u64()
        element.data_element_hash = (scheme, reader.binary_item())
    reader.expect_start(SO_OBJECT_GROUP_DECLARATIONS)
    while True:
        header = reader.header()
        if header.kind in ("end8", "end16"):
            if header.type != SO_OBJECT_GROUP_DECLARATIONS:
                raise FsshttpbDecodeError(f"unexpected end 0x{header.type:x} in declarations")
            break
        if header.type == SO_OBJECT_DECLARATION:
            element.declarations.append(
                ObjectDeclaration(
                    exguid=reader.exguid(),
                    partition_id=reader.compact_u64(),
                    data_size=reader.compact_u64(),
                    object_references_count=reader.compact_u64(),
                    cell_references_count=reader.compact_u64(),
                )
            )
        elif header.type == SO_OBJECT_DATA_BLOB_DECLARATION:
            exguid = reader.exguid()
            blob = reader.exguid()
            element.declarations.append(
                ObjectDeclaration(
                    exguid=exguid,
                    partition_id=reader.compact_u64(),
                    data_size=None,
                    object_references_count=reader.compact_u64(),
                    cell_references_count=reader.compact_u64(),
                    blob_exguid=blob,
                )
            )
        else:
            raise FsshttpbDecodeError(f"unexpected 0x{header.type:x} in object declarations")
    header = reader.peek_header()
    if header.kind.startswith("start") and header.type == SO_OBJECT_GROUP_METADATA_DECLARATIONS:
        reader.header()
        while True:
            header = reader.header()
            if header.kind in ("end8", "end16"):
                if header.type != SO_OBJECT_GROUP_METADATA_DECLARATIONS:
                    raise FsshttpbDecodeError("bad object metadata declarations end")
                break
            if header.type != SO_OBJECT_GROUP_METADATA:
                raise FsshttpbDecodeError(f"unexpected 0x{header.type:x} in object metadata")
            element.metadata.append(reader.compact_u64())
    reader.expect_start(SO_OBJECT_GROUP_DATA)
    while True:
        header = reader.header()
        if header.kind in ("end8", "end16"):
            if header.type != SO_OBJECT_GROUP_DATA:
                raise FsshttpbDecodeError(f"unexpected end 0x{header.type:x} in object data")
            break
        body_end = reader.pos + header.length
        if header.type == SO_OBJECT_DATA:
            refs = reader.exguid_array()
            cells = reader.cell_id_array()
            data = reader.binary_item()
            element.objects.append(ObjectData("data", refs, cells, data=data))
        elif header.type == SO_OBJECT_EXCLUDED_DATA:
            refs = reader.exguid_array()
            cells = reader.cell_id_array()
            element.objects.append(
                ObjectData("excluded", refs, cells, excluded_size=reader.compact_u64())
            )
        elif header.type == SO_OBJECT_DATA_BLOB_REFERENCE:
            refs = reader.exguid_array()
            cells = reader.cell_id_array()
            element.objects.append(
                ObjectData("blob_reference", refs, cells, blob_exguid=reader.exguid())
            )
        else:
            raise FsshttpbDecodeError(f"unexpected 0x{header.type:x} in object data")
        if reader.pos != body_end:
            raise FsshttpbDecodeError(
                f"object data stream object length mismatch: header says end "
                f"0x{body_end:x}, parsed to 0x{reader.pos:x}"
            )


def parse_data_element(reader: Reader) -> DataElement:


    start = reader.pos
    header = reader.expect_start(SO_DATA_ELEMENT)
    if not header.compound:
        raise FsshttpbDecodeError("data element start must be compound")
    exguid = reader.exguid()
    serial = reader.serial()
    de_type = reader.compact_u64()
    element = DataElement(exguid=exguid, serial=serial, type=de_type, offset=start, size=0)
    if de_type == DE_OBJECT_GROUP:
        _parse_object_group(reader, element)
    elif de_type == DE_DATA_ELEMENT_FRAGMENT:
        frag = reader.expect_start(SO_DATA_ELEMENT_FRAGMENT)
        body_start = reader.pos
        fragment_id = reader.exguid()
        total = reader.compact_u64()
        chunk_start = reader.compact_u64()
        chunk_length = reader.compact_u64()
        consumed = reader.pos - body_start
        data = reader.take(frag.length - consumed) if frag.length >= consumed else b""
        element.fragment = {
            "fragment_exguid": fragment_id,
            "data_element_size": total,
            "chunk_start": chunk_start,
            "chunk_length": chunk_length,
            "data": data,
        }
    elif de_type == DE_OBJECT_DATA_BLOB:
        blob = reader.expect_start(SO_OBJECT_DATA_BLOB)
        element.blob_data = reader.take(blob.length)
    else:
        while True:
            header = reader.header()
            if header.kind in ("end8", "end16"):
                if header.type != SO_DATA_ELEMENT:
                    raise FsshttpbDecodeError(f"unexpected end 0x{header.type:x}")
                element.size = reader.pos - start
                return element
            body_end = reader.pos + header.length
            if de_type == DE_STORAGE_INDEX and header.type == SO_STORAGE_INDEX_MANIFEST_MAPPING:
                element.manifest_mappings.append((reader.exguid(), reader.serial()))
            elif de_type == DE_STORAGE_INDEX and header.type == SO_STORAGE_INDEX_CELL_MAPPING:
                element.cell_mappings.append((reader.cell_id(), reader.exguid(), reader.serial()))
            elif de_type == DE_STORAGE_INDEX and header.type == SO_STORAGE_INDEX_REVISION_MAPPING:
                element.revision_mappings.append(
                    (reader.exguid(), reader.exguid(), reader.serial())
                )
            elif de_type == DE_STORAGE_MANIFEST and header.type == SO_STORAGE_MANIFEST_SCHEMA_GUID:
                element.schema_guid = reader.guid()
            elif de_type == DE_STORAGE_MANIFEST and header.type == SO_STORAGE_MANIFEST_ROOT_DECLARE:
                element.storage_roots.append((reader.exguid(), reader.cell_id()))
            elif de_type == DE_CELL_MANIFEST and header.type == SO_CELL_MANIFEST_CURRENT_REVISION:
                element.current_revision = reader.exguid()
            elif de_type == DE_REVISION_MANIFEST and header.type == SO_REVISION_MANIFEST:
                element.revision_id = reader.exguid()
                element.base_revision_id = reader.exguid()
            elif (
                de_type == DE_REVISION_MANIFEST
                and header.type == SO_REVISION_MANIFEST_ROOT_DECLARE
            ):
                element.revision_roots.append((reader.exguid(), reader.exguid()))
            elif (
                de_type == DE_REVISION_MANIFEST
                and header.type == SO_REVISION_MANIFEST_OBJECT_GROUP_REFERENCES
            ):
                element.object_group_references.append(reader.exguid())
            else:
                raise FsshttpbDecodeError(
                    f"unexpected stream object 0x{header.type:x} in data element type "
                    f"0x{de_type:x}"
                )
            if reader.pos != body_end:
                raise FsshttpbDecodeError(
                    f"stream object 0x{header.type:x} length mismatch: header end "
                    f"0x{body_end:x}, parsed to 0x{reader.pos:x}"
                )
    reader.expect_end(SO_DATA_ELEMENT)
    element.size = reader.pos - start
    return element


@dataclass
class BlobHeapRecord:
    flag: int
    elements: list[DataElement]
    trailing: bytes


def parse_blobheap_record(data: bytes) -> BlobHeapRecord:


    if len(data) < BLOBHEAP_HEADER_SIZE:
        raise FsshttpbDecodeError("blob is shorter than the BlobHeap header")
    magic, flag = struct.unpack_from("<IB", data)
    if magic != BLOBHEAP_MAGIC:
        raise FsshttpbDecodeError(f"BlobHeap signature 0x{magic:08x} != 0x{BLOBHEAP_MAGIC:08x}")
    reader = Reader(data, BLOBHEAP_HEADER_SIZE)
    elements = []
    while reader.remaining:
        peek = reader.peek(2)
        if len(peek) == 2 and (peek[0] & 0x03) == 0 and ((int.from_bytes(peek, "little") >> 3) & 0x3F) == SO_DATA_ELEMENT:
            elements.append(parse_data_element(reader))
        else:
            break
    return BlobHeapRecord(flag=flag, elements=elements, trailing=reader.data[reader.pos :])
