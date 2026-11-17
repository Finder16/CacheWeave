

from __future__ import annotations

import argparse
import json
import uuid
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from ..formats.terse_codec import (
    TerseDecodeError,
    TerseReader,
    build_envelope,
    decode_envelope,
    encode_uleb128,
    storage_crc32,
    zigzag_encode,
)
from .syzygy_encryption_providers import provider_name
from .syzygy_crypt_session import parse_crypt_session_prefix


VAULT_FORMAT_VERSION = 1


class VaultDecodeError(ValueError):
    pass


@dataclass(frozen=True)
class VaultSession:
    session_id: int
    declared_secret_size: int
    secret: bytes
    serialized_value: bytes
    active: bool
    created_timestamp: int
    flags: int

    def to_json_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["secret"] = self.secret.hex()
        result["serialized_value"] = self.serialized_value.hex()
        try:
            prefix = parse_crypt_session_prefix(self.serialized_value)
        except ValueError as error:
            result["crypt_session"] = {"recognized": False, "error": str(error)}
        else:
            result["crypt_session"] = {
                "recognized": True,
                "version": prefix.version,
                "compatibility_version": prefix.compatibility_version,
                "crypto_type": f"0x{prefix.crypto_type:08x}",
                "crypto_xml_size": len(prefix.crypto_xml),
                "secret_size_matches_utf16_units": (
                    len(self.secret) == self.declared_secret_size * 2
                ),
            }
        return result


@dataclass(frozen=True)
class VaultSessions:
    sessions: tuple[VaultSession, ...]

    def to_json_dict(self) -> dict[str, Any]:
        return {"sessions": [session.to_json_dict() for session in self.sessions]}


@dataclass(frozen=True)
class VaultEnvelope:
    version: int
    checksum: int
    provider_ids: tuple[str, ...]
    sessions_blob: bytes
    sessions: VaultSessions | None

    @property
    def encrypted(self) -> bool:
        return bool(self.provider_ids)

    def to_json_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "checksum": f"0x{self.checksum:08x}",
            "provider_ids": list(self.provider_ids),
            "providers": [
                {"id": provider_id, "name": provider_name(provider_id)}
                for provider_id in self.provider_ids
            ],
            "encrypted": self.encrypted,
            "sessions_blob_size": len(self.sessions_blob),
            "sessions_blob": self.sessions_blob.hex(),
            "sessions": None if self.sessions is None else self.sessions.to_json_dict(),
        }


def _read_bool_uleb(reader: TerseReader, label: str) -> bool:
    value = reader.read_uleb128(32)
    if value not in (0, 1):
        raise VaultDecodeError(f"{label} has invalid boolean value {value}")
    return bool(value)


def decode_vault_sessions(data: bytes) -> VaultSessions:


    try:
        reader = TerseReader(bytes(data))
        count = reader.read_uleb128(32)
        sessions: list[VaultSession] = []
        seen_ids: set[int] = set()
        for index in range(count):
            session_id = reader.read_uleb128(32)
            declared_secret_size = reader.read_uleb128(32)
            secret = reader.read_byte_vector()
            serialized_value = reader.read_byte_vector()
            active = _read_bool_uleb(reader, f"session {index} active")
            created_timestamp = reader.read_signed(64)
            flags = reader.read_exact(1)[0]
            if session_id in seen_ids:
                raise VaultDecodeError(f"duplicate session id {session_id}")
            seen_ids.add(session_id)
            sessions.append(
                VaultSession(
                    session_id=session_id,
                    declared_secret_size=declared_secret_size,
                    secret=secret,
                    serialized_value=serialized_value,
                    active=active,
                    created_timestamp=created_timestamp,
                    flags=flags,
                )
            )
        if not reader.finished:
            raise VaultDecodeError(
                f"inner sessions payload has {reader.remaining} trailing bytes"
            )
    except TerseDecodeError as error:
        raise VaultDecodeError(f"invalid inner sessions stream: {error}") from error
    return VaultSessions(tuple(sessions))


def decode_vault(data: bytes) -> VaultEnvelope:


    try:
        envelope = decode_envelope(data)
        reader = TerseReader(envelope.payload)
        version = reader.read_uleb128(16)
        checksum = reader.read_uleb128(32)
        provider_count = reader.read_uleb128(32)
        provider_ids = tuple(
            str(uuid.UUID(bytes_le=reader.read_exact(16)))
            for _ in range(provider_count)
        )
        sessions_blob = reader.read_byte_vector()
        if not reader.finished:
            raise VaultDecodeError(
                f"outer vault payload has {reader.remaining} trailing bytes"
            )
    except TerseDecodeError as error:
        raise VaultDecodeError(f"invalid outer vault stream: {error}") from error
    if version != VAULT_FORMAT_VERSION:
        raise VaultDecodeError(
            f"unsupported vault version {version}, expected {VAULT_FORMAT_VERSION}"
        )
    actual_checksum = storage_crc32(sessions_blob)
    if checksum != actual_checksum:
        raise VaultDecodeError(
            f"sessions checksum mismatch: stored 0x{checksum:08x}, "
            f"actual 0x{actual_checksum:08x}"
        )
    sessions = None if provider_ids else decode_vault_sessions(sessions_blob)
    return VaultEnvelope(
        version=version,
        checksum=checksum,
        provider_ids=provider_ids,
        sessions_blob=sessions_blob,
        sessions=sessions,
    )


def build_vault_sessions(sessions: tuple[VaultSession, ...]) -> bytes:


    payload = bytearray(encode_uleb128(len(sessions), 32))
    seen_ids: set[int] = set()
    for session in sessions:
        if session.session_id in seen_ids:
            raise ValueError(f"duplicate session id {session.session_id}")
        seen_ids.add(session.session_id)
        if not 0 <= session.flags <= 0xFF:
            raise ValueError("session flags must fit one byte")
        payload.extend(encode_uleb128(session.session_id, 32))
        payload.extend(encode_uleb128(session.declared_secret_size, 32))
        payload.extend(encode_uleb128(len(session.secret), 32))
        payload.extend(session.secret)
        payload.extend(encode_uleb128(len(session.serialized_value), 32))
        payload.extend(session.serialized_value)
        payload.extend(encode_uleb128(int(session.active), 32))
        payload.extend(encode_uleb128(zigzag_encode(session.created_timestamp, 64), 64))
        payload.append(session.flags)
    return bytes(payload)


def build_vault(
    sessions_blob: bytes,
    provider_ids: tuple[str, ...] = (),
) -> bytes:


    payload = bytearray(encode_uleb128(VAULT_FORMAT_VERSION, 16))
    payload.extend(encode_uleb128(storage_crc32(sessions_blob), 32))
    payload.extend(encode_uleb128(len(provider_ids), 32))
    for provider_id in provider_ids:
        payload.extend(uuid.UUID(provider_id).bytes_le)
    payload.extend(encode_uleb128(len(sessions_blob), 32))
    payload.extend(sessions_blob)
    return build_envelope(bytes(payload))


def main() -> int:
    parser = argparse.ArgumentParser(
        description="validate/decode a Syzygy _vault resident property"
    )
    parser.add_argument("vault", type=Path)
    args = parser.parse_args()
    try:
        decoded = decode_vault(args.vault.read_bytes())
    except (OSError, VaultDecodeError) as error:
        parser.error(str(error))
    print(json.dumps(decoded.to_json_dict(), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
