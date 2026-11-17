

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
from pathlib import Path
from typing import Any

from ..formats.terse_codec import (
    TerseDecodeError,
    TerseReader,
    build_envelope,
    decode_envelope,
    encode_uleb128,
)


STANDARD_DPAPI_PROVIDER_ID = "54bd1499-7413-472f-8835-d19454db7952"
ENTERPRISE_DATA_PROVIDER_ID = "fb19597b-51db-40fb-ae2a-62acd2195bec"
IRM_PROVIDER_ID = "65e11c58-98f0-47f8-92a4-b3ecadd5b4d1"

KNOWN_PROVIDER_NAMES = {
    STANDARD_DPAPI_PROVIDER_ID: "standard-dpapi-machine",
    ENTERPRISE_DATA_PROVIDER_ID: "enterprise-data-protection",
    IRM_PROVIDER_ID: "information-rights-management",
}

IRM_SCHEMA_VERSION = 1
IRM_KEY_SEED_SIZE = 0x20
IRM_MAC_SIZE = 0x20
IRM_INTEGRITY_OVERHEAD = IRM_KEY_SEED_SIZE + IRM_MAC_SIZE
IRM_KEY_DERIVATION_CONTEXT = b"\x01PlaintextHmacKey\x00\x01\x00"


class ProviderDecodeError(ValueError):
    pass


def provider_name(provider_id: str) -> str | None:


    return KNOWN_PROVIDER_NAMES.get(provider_id.lower())


def derive_irm_integrity_key(key_seed: bytes) -> bytes:


    if len(key_seed) != IRM_KEY_SEED_SIZE:
        raise ValueError(
            f"IRM key seed must be 0x{IRM_KEY_SEED_SIZE:x} bytes, "
            f"got 0x{len(key_seed):x}"
        )
    return hmac.new(
        key_seed,
        IRM_KEY_DERIVATION_CONTEXT,
        hashlib.sha256,
    ).digest()


def add_irm_integrity(plaintext: bytes, key_seed: bytes) -> bytes:


    integrity_key = derive_irm_integrity_key(key_seed)
    authenticated = plaintext + key_seed
    mac = hmac.new(integrity_key, authenticated, hashlib.sha256).digest()
    return authenticated + mac


def verify_and_strip_irm_integrity(data: bytes) -> bytes:


    if len(data) <= IRM_INTEGRITY_OVERHEAD:
        raise ProviderDecodeError(
            "IRM integrity value must contain nonempty plaintext plus "
            "a 0x20-byte key seed and 0x20-byte MAC"
        )
    plaintext_end = len(data) - IRM_INTEGRITY_OVERHEAD
    key_seed_end = len(data) - IRM_MAC_SIZE
    key_seed = data[plaintext_end:key_seed_end]
    stored_mac = data[key_seed_end:]
    integrity_key = derive_irm_integrity_key(key_seed)
    actual_mac = hmac.new(
        integrity_key,
        data[:key_seed_end],
        hashlib.sha256,
    ).digest()
    if not hmac.compare_digest(stored_mac, actual_mac):
        raise ProviderDecodeError("IRM HMAC-SHA256 verification failed")
    return data[:plaintext_end]


def build_irm_plaintext_stream(plaintext: bytes) -> bytes:


    payload = (
        encode_uleb128(IRM_SCHEMA_VERSION, 32)
        + encode_uleb128(len(plaintext), 32)
        + plaintext
    )
    return build_envelope(payload)


def decode_irm_plaintext_stream(data: bytes) -> bytes:


    try:
        envelope = decode_envelope(data)
        reader = TerseReader(envelope.payload)
        version = reader.read_uleb128(32)
        if version != IRM_SCHEMA_VERSION:
            raise ProviderDecodeError(
                f"unsupported IRM schema version {version}, "
                f"expected {IRM_SCHEMA_VERSION}"
            )
        plaintext = reader.read_byte_vector()
        if not reader.finished:
            raise ProviderDecodeError(
                f"IRM plaintext payload has {reader.remaining} trailing bytes"
            )
    except TerseDecodeError as error:
        raise ProviderDecodeError(f"invalid IRM Terse stream: {error}") from error
    return plaintext


def inspect_irm_integrity(data: bytes) -> dict[str, Any]:


    terse_stream = verify_and_strip_irm_integrity(data)
    plaintext = decode_irm_plaintext_stream(terse_stream)
    return {
        "integrity_algorithm": "HMAC-SHA256",
        "key_seed_size": IRM_KEY_SEED_SIZE,
        "mac_size": IRM_MAC_SIZE,
        "terse_stream_size": len(terse_stream),
        "plaintext_size": len(plaintext),
        "plaintext_sha256": hashlib.sha256(plaintext).hexdigest(),
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="identify Syzygy providers or inspect post-IRM-decryption bytes"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    provider_parser = subparsers.add_parser("provider")
    provider_parser.add_argument("guid")
    irm_parser = subparsers.add_parser("irm-integrity")
    irm_parser.add_argument("stream", type=Path)
    args = parser.parse_args()

    try:
        if args.command == "provider":
            name = provider_name(args.guid)
            print(json.dumps({"provider_id": args.guid.lower(), "name": name}))
            return 0 if name is not None else 1
        result = inspect_irm_integrity(args.stream.read_bytes())
        print(json.dumps(result, indent=2))
        return 0
    except (OSError, ProviderDecodeError, ValueError) as error:
        parser.error(str(error))
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
