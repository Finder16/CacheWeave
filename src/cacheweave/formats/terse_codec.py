

from __future__ import annotations

import argparse
import json
import struct
import uuid
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


TERSE_V2 = 2
TERSE_V2_HEADER_SIZE = 9
CRC_POLYNOMIAL = 0x000000AF


class TerseDecodeError(ValueError):
    pass


def _build_crc_table() -> tuple[int, ...]:
    table: list[int] = []
    for index in range(256):
        value = index << 24
        for _ in range(8):
            if value & 0x80000000:
                value = ((value << 1) ^ CRC_POLYNOMIAL) & 0xFFFFFFFF
            else:
                value = (value << 1) & 0xFFFFFFFF
        table.append(value)
    return tuple(table)


CRC_TABLE = _build_crc_table()


def storage_crc32(data: bytes | bytearray | memoryview, initial: int = 0) -> int:


    checksum = initial & 0xFFFFFFFF
    for byte in memoryview(data).cast("B"):
        index = ((checksum >> 24) ^ byte) & 0xFF
        checksum = ((checksum << 8) ^ CRC_TABLE[index]) & 0xFFFFFFFF
    return checksum


def encode_uleb128(value: int, bits: int = 64) -> bytes:
    if value < 0 or value >= 1 << bits:
        raise ValueError(f"value does not fit unsigned {bits}-bit integer")
    encoded = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        encoded.append(byte | (0x80 if value else 0))
        if not value:
            return bytes(encoded)


def zigzag_decode(value: int, bits: int) -> int:
    mask = (1 << bits) - 1
    value &= mask
    return (value >> 1) ^ -(value & 1)


def zigzag_encode(value: int, bits: int) -> int:
    minimum = -(1 << (bits - 1))
    maximum = (1 << (bits - 1)) - 1
    if not minimum <= value <= maximum:
        raise ValueError(f"value does not fit signed {bits}-bit integer")
    return ((value << 1) ^ (value >> (bits - 1))) & ((1 << bits) - 1)


class TerseReader:


    def __init__(self, data: bytes | bytearray | memoryview):
        self._data = memoryview(data).cast("B")
        self.offset = 0

    @property
    def size(self) -> int:
        return len(self._data)

    @property
    def remaining(self) -> int:
        return self.size - self.offset

    @property
    def finished(self) -> bool:
        return self.offset == self.size

    def read_exact(self, count: int) -> bytes:
        if count < 0:
            raise TerseDecodeError("negative byte count")
        end = self.offset + count
        if end > self.size:
            raise TerseDecodeError(
                f"truncated payload at offset {self.offset}: need {count}, "
                f"have {self.remaining}"
            )
        result = self._data[self.offset:end].tobytes()
        self.offset = end
        return result

    def read_uleb128(self, bits: int = 64) -> int:
        if bits <= 0:
            raise ValueError("bits must be positive")
        value = 0
        shift = 0
        maximum_bytes = (bits + 6) // 7
        for index in range(maximum_bytes):
            byte = self.read_exact(1)[0]
            payload = byte & 0x7F
            if shift >= bits or payload > (((1 << bits) - 1) >> shift):
                raise TerseDecodeError(
                    f"ULEB128 overflow for uint{bits} at offset {self.offset - 1}"
                )
            value |= payload << shift
            if not byte & 0x80:
                return value
            shift += 7
        raise TerseDecodeError(
            f"unterminated or overflowing uint{bits} ULEB128 at offset "
            f"{self.offset - maximum_bytes}"
        )

    def read_signed(self, bits: int) -> int:
        return zigzag_decode(self.read_uleb128(bits), bits)

    def read_bool(self) -> bool:
        value = self.read_exact(1)[0]
        if value not in (0, 1):
            raise TerseDecodeError(
                f"invalid bool value {value} at offset {self.offset - 1}"
            )
        return bool(value)

    def read_guid(self) -> dict[str, str]:
        raw = self.read_exact(16)
        return {"guid": str(uuid.UUID(bytes_le=raw)), "raw_hex": raw.hex()}

    def read_byte_vector(self) -> bytes:
        count = self.read_uleb128(32)
        return self.read_exact(count)

    def read_string(self) -> str:


        raw = self.read_byte_vector()
        try:
            return raw.decode("utf-8", errors="strict")
        except UnicodeDecodeError:


            return raw.decode("latin-1")

    def read_wstring(self) -> str:
        count = self.read_uleb128(32)
        code_units = [self.read_uleb128(16) for _ in range(count)]
        raw = b"".join(struct.pack("<H", unit) for unit in code_units)
        try:
            return raw.decode("utf-16-le", errors="strict")
        except UnicodeDecodeError as error:
            raise TerseDecodeError(
                f"invalid UTF-16 string ending at offset {self.offset}"
            ) from error


@dataclass(frozen=True)
class TerseEnvelope:
    version: int
    checksum: int
    payload_size: int
    payload: bytes
    trailing_size: int

    def to_json_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["checksum"] = f"0x{self.checksum:08x}"
        result["payload"] = self.payload.hex()
        return result


def decode_envelope(
    data: bytes | bytearray | memoryview,
    *,
    allow_trailing: bool = False,
) -> TerseEnvelope:


    raw = bytes(data)
    if len(raw) < TERSE_V2_HEADER_SIZE:
        raise TerseDecodeError(
            f"Terse v2 stream is {len(raw)} bytes, need at least 9"
        )
    version, checksum, payload_size = struct.unpack_from("<BII", raw)
    if version != TERSE_V2:
        raise TerseDecodeError(f"unsupported Terse version {version}, expected 2")
    available = len(raw) - TERSE_V2_HEADER_SIZE
    if payload_size > available:
        raise TerseDecodeError(
            f"declared payload is {payload_size} bytes, only {available} available"
        )
    if not allow_trailing and payload_size != available:
        raise TerseDecodeError(
            f"declared payload is {payload_size} bytes but stream contains {available}"
        )
    payload = raw[TERSE_V2_HEADER_SIZE : TERSE_V2_HEADER_SIZE + payload_size]
    actual = storage_crc32(payload)
    if actual != checksum:
        raise TerseDecodeError(
            f"checksum mismatch: header 0x{checksum:08x}, actual 0x{actual:08x}"
        )
    return TerseEnvelope(
        version=version,
        checksum=checksum,
        payload_size=payload_size,
        payload=payload,
        trailing_size=available - payload_size,
    )


def build_envelope(payload: bytes, version: int = TERSE_V2) -> bytes:


    if version != TERSE_V2:
        raise ValueError("only recovered Terse version 2 can be emitted")
    return struct.pack("<BII", version, storage_crc32(payload), len(payload)) + payload


METADATA_VALUE_TYPES = {
    1: "bool",
    2: "bytes",
    3: "guid",
    4: "uint16",
    5: "uint32",
    6: "uint64",
    7: "wstring",
}


@dataclass(frozen=True)
class MetadataElement:
    key: int
    type_id: int
    type_name: str
    value: Any

    def to_json_dict(self) -> dict[str, Any]:
        value = self.value.hex() if isinstance(self.value, bytes) else self.value
        return {
            "key": f"0x{self.key:016x}",
            "type_id": self.type_id,
            "type_name": self.type_name,
            "value": value,
        }


@dataclass(frozen=True)
class DocumentMetadata:
    stream_version: int
    declared_element_count: int
    elements: tuple[MetadataElement, ...]

    def to_json_dict(self) -> dict[str, Any]:
        return {
            "stream_version": self.stream_version,
            "declared_element_count": self.declared_element_count,
            "elements": [element.to_json_dict() for element in self.elements],
        }


def _read_metadata_value(reader: TerseReader, type_id: int) -> Any:
    if type_id == 1:
        return reader.read_bool()
    if type_id == 2:
        return reader.read_byte_vector()
    if type_id == 3:
        return reader.read_guid()
    if type_id == 4:
        return reader.read_uleb128(16)
    if type_id == 5:
        return reader.read_uleb128(32)
    if type_id == 6:
        return reader.read_uleb128(64)
    if type_id == 7:
        return reader.read_wstring()
    raise TerseDecodeError(f"unsupported DocumentMetadata type id {type_id}")


def decode_document_metadata_payload(payload: bytes) -> DocumentMetadata:


    reader = TerseReader(payload)
    stream_version = reader.read_uleb128(16)
    count = reader.read_uleb128(16)
    if stream_version < 6:
        raise TerseDecodeError(
            "DocumentMetadata versions below 6 omit type ids and require the "
            "version-specific key map"
        )
    elements: list[MetadataElement] = []
    for index in range(count):
        try:
            key = reader.read_uleb128(64)
            type_id = reader.read_uleb128(64)
            type_name = METADATA_VALUE_TYPES.get(type_id)
            if type_name is None:
                raise TerseDecodeError(
                    f"unknown metadata type id {type_id} for element {index}"
                )
            value = _read_metadata_value(reader, type_id)
        except TerseDecodeError as error:
            raise TerseDecodeError(f"element {index}: {error}") from error
        elements.append(MetadataElement(key, type_id, type_name, value))
    if not reader.finished:
        raise TerseDecodeError(
            f"DocumentMetadata has {reader.remaining} trailing payload bytes"
        )
    return DocumentMetadata(stream_version, count, tuple(elements))


def decode_document_metadata(data: bytes, *, allow_trailing: bool = False) -> DocumentMetadata:
    return decode_document_metadata_payload(
        decode_envelope(data, allow_trailing=allow_trailing).payload
    )


AUDIT_LOG_VERSION = 1
AUDIT_TRACE_COUNT = 0x1000


@dataclass(frozen=True)
class AuditTrace:
    sequence_number: int
    process_id: int
    test_locus_u16: int
    payload_word_0: int
    payload_word_1: int

    @property
    def payload(self) -> bytes:


        return self.payload_word_0.to_bytes(8, "little") + self.payload_word_1.to_bytes(
            8, "little"
        )

    def to_json_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["payload_hex"] = self.payload.hex()
        return result


@dataclass(frozen=True)
class AuditLog:
    version: int
    ring_cursor: int
    traces: tuple[AuditTrace, ...]

    def to_json_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "ring_cursor": self.ring_cursor,
            "trace_count": len(self.traces),
            "traces": [trace.to_json_dict() for trace in self.traces],
        }


def decode_audit_log_payload(payload: bytes) -> AuditLog:


    reader = TerseReader(payload)
    version = reader.read_uleb128(8)
    if version != AUDIT_LOG_VERSION:
        raise TerseDecodeError(
            f"unsupported AuditLog version {version}, expected {AUDIT_LOG_VERSION}"
        )
    ring_cursor = reader.read_uleb128(64)
    if ring_cursor >= AUDIT_TRACE_COUNT:
        raise TerseDecodeError(
            f"AuditLog ring cursor {ring_cursor} is outside the 4096-slot ring"
        )
    traces: list[AuditTrace] = []
    for index in range(AUDIT_TRACE_COUNT):
        try:
            traces.append(
                AuditTrace(
                    sequence_number=reader.read_uleb128(32),
                    process_id=reader.read_uleb128(32),
                    test_locus_u16=reader.read_uleb128(16),
                    payload_word_0=reader.read_uleb128(64),
                    payload_word_1=reader.read_uleb128(64),
                )
            )
        except TerseDecodeError as error:
            raise TerseDecodeError(f"AuditLog trace {index}: {error}") from error
    if not reader.finished:
        raise TerseDecodeError(f"AuditLog has {reader.remaining} trailing payload bytes")
    return AuditLog(version, ring_cursor, tuple(traces))


def decode_audit_log(data: bytes, *, allow_trailing: bool = False) -> AuditLog:
    return decode_audit_log_payload(
        decode_envelope(data, allow_trailing=allow_trailing).payload
    )


@dataclass(frozen=True)
class LastOcsSave:
    sequence_number: int
    ocs_match: bool
    ocs_session_id: str

    def to_json_dict(self) -> dict[str, Any]:
        return asdict(self)


def decode_last_ocs_save_payload(payload: bytes) -> LastOcsSave:


    reader = TerseReader(payload)
    value = LastOcsSave(
        sequence_number=reader.read_uleb128(64),
        ocs_match=reader.read_bool(),
        ocs_session_id=reader.read_string(),
    )
    if not reader.finished:
        raise TerseDecodeError(
            f"LastOcsSave has {reader.remaining} trailing payload bytes"
        )
    return value


def decode_last_ocs_save(
    data: bytes, *, allow_trailing: bool = False
) -> LastOcsSave:
    return decode_last_ocs_save_payload(
        decode_envelope(data, allow_trailing=allow_trailing).payload
    )


@dataclass(frozen=True)
class RevisionClockData:


    wstring_field: str
    opaque_16: bytes
    uint32_field: int
    trailing_bytes: bytes

    def to_json_dict(self) -> dict[str, Any]:
        return {
            "wstring_field": self.wstring_field,
            "opaque_16": self.opaque_16.hex(),
            "uint32_field": self.uint32_field,
            "trailing_size": len(self.trailing_bytes),
            "trailing_bytes": self.trailing_bytes.hex(),
        }


def decode_revision_clock_data(data: bytes) -> RevisionClockData:


    reader = TerseReader(data)
    wstring_field = reader.read_wstring()
    opaque_16 = reader.read_byte_vector()
    if len(opaque_16) != 16:
        raise TerseDecodeError(
            f"RevisionClockData opaque field must be 16 bytes, got {len(opaque_16)}"
        )
    uint32_field = reader.read_uleb128(32)
    trailing_bytes = reader.read_exact(reader.remaining)
    return RevisionClockData(
        wstring_field=wstring_field,
        opaque_16=opaque_16,
        uint32_field=uint32_field,
        trailing_bytes=trailing_bytes,
    )


def _main() -> int:
    parser = argparse.ArgumentParser(
        description="validate/decode an Office Storage::Terse v2 stream"
    )
    parser.add_argument("path", type=Path)
    payload_kind = parser.add_mutually_exclusive_group()
    payload_kind.add_argument(
        "--metadata",
        action="store_true",
        help="decode the payload as DRG DocumentMetadata",
    )
    payload_kind.add_argument(
        "--audit-log",
        action="store_true",
        help="decode the payload as the fixed-size DRG AuditLog",
    )
    payload_kind.add_argument(
        "--last-ocs-save",
        action="store_true",
        help="decode the payload as a revision LastOcsSave record",
    )
    payload_kind.add_argument(
        "--revision-clock-data",
        action="store_true",
        help="decode the complete input as headerless Terse v1 RevisionClockData",
    )
    parser.add_argument(
        "--allow-trailing",
        action="store_true",
        help="mirror Terse reader flag bit 1 and allow bytes after declared payload",
    )
    args = parser.parse_args()
    try:
        if args.revision_clock_data:
            result = {
                "revision_clock_data": decode_revision_clock_data(
                    args.path.read_bytes()
                ).to_json_dict()
            }
            print(json.dumps(result, indent=2, ensure_ascii=False))
            return 0
        envelope = decode_envelope(
            args.path.read_bytes(), allow_trailing=args.allow_trailing
        )
        result: dict[str, Any] = {"envelope": envelope.to_json_dict()}
        if args.metadata:
            result["document_metadata"] = decode_document_metadata_payload(
                envelope.payload
            ).to_json_dict()
        elif args.audit_log:
            result["audit_log"] = decode_audit_log_payload(
                envelope.payload
            ).to_json_dict()
        elif args.last_ocs_save:
            result["last_ocs_save"] = decode_last_ocs_save_payload(
                envelope.payload
            ).to_json_dict()
        print(json.dumps(result, indent=2, ensure_ascii=False))
    except (OSError, TerseDecodeError) as error:
        parser.error(str(error))
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
