


from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import hmac
import json
import struct
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path


CURRENT_SECRET_CODE_UNITS = 0x20
CURRENT_SECRET_BYTES = CURRENT_SECRET_CODE_UNITS * 2
CURRENT_SALT_BYTES = 0x10
CURRENT_HASH_BYTES = 0x40
CURRENT_PASSWORD_SPIN_COUNT = 0
CURRENT_KEY_BITS = 0x100
CURRENT_KEY_BYTES = CURRENT_KEY_BITS // 8
CURRENT_BLOCK_BYTES = 0x10
CURRENT_CRYPTO_ALGORITHM = "AES"
CURRENT_HASH_ALGORITHM = "SHA512"
CURRENT_CHAINING_MODE = "ChainingModeCBC"

CURRENT_SESSION_VERSION = 4
CURRENT_COMPAT_VERSION = 4
CURRENT_CRYPTO_TYPE = 0x40
_SESSION_PREFIX = struct.Struct("<HHI")

ENCRYPTED_VERIFIER_INPUT_BLOCK_KEY = bytes.fromhex("fea7d2763b4b9e79")
ENCRYPTED_VERIFIER_HASH_BLOCK_KEY = bytes.fromhex("d7aa0f6d3061344e")
ENCRYPTED_KEY_VALUE_BLOCK_KEY = bytes.fromhex("146e0be7abacd0d6")
AGILE_ENCRYPTED_HMAC_KEY_BLOCK_KEY = bytes.fromhex("5fb2ad010cb9e1f6")
AGILE_ENCRYPTED_HMAC_VALUE_BLOCK_KEY = bytes.fromhex("a0677f02b22c8433")

HMAC_KEY_RESET_TAG = 0x0B511C03
POST_HMAC_RESET_TAG = 0x033BECAB


@dataclass(frozen=True)
class EncryptionParameters:
    salt: bytes
    salt_size: int
    block_size: int
    key_bits: int
    hash_size: int
    cipher_algorithm: str
    cipher_chaining: str
    hash_algorithm: str

    def to_json(self) -> dict[str, object]:
        return {
            "salt": self.salt.hex(),
            "salt_size": self.salt_size,
            "block_size": self.block_size,
            "key_bits": self.key_bits,
            "hash_size": self.hash_size,
            "cipher_algorithm": self.cipher_algorithm,
            "cipher_chaining": self.cipher_chaining,
            "hash_algorithm": self.hash_algorithm,
        }


@dataclass(frozen=True)
class PasswordEncryptor:
    parameters: EncryptionParameters
    spin_count: int
    encrypted_verifier_hash_input: bytes
    encrypted_verifier_hash_value: bytes
    encrypted_key_value: bytes

    def to_json(self) -> dict[str, object]:
        return {
            **self.parameters.to_json(),
            "spin_count": self.spin_count,
            "encrypted_verifier_hash_input": self.encrypted_verifier_hash_input.hex(),
            "encrypted_verifier_hash_value": self.encrypted_verifier_hash_value.hex(),
            "encrypted_key_value": self.encrypted_key_value.hex(),
        }


@dataclass(frozen=True)
class AgileDataIntegrity:
    encrypted_hmac_key: bytes
    encrypted_hmac_value: bytes

    def to_json(self) -> dict[str, str]:
        return {
            "encrypted_hmac_key": self.encrypted_hmac_key.hex(),
            "encrypted_hmac_value": self.encrypted_hmac_value.hex(),
        }


@dataclass(frozen=True)
class CryptSessionDescriptor:
    key_data: EncryptionParameters
    password_encryptor: PasswordEncryptor
    data_integrity: AgileDataIntegrity | None = None

    def to_json(self) -> dict[str, object]:
        return {
            "key_data": self.key_data.to_json(),
            "password_encryptor": self.password_encryptor.to_json(),
            "data_integrity": (
                self.data_integrity.to_json()
                if self.data_integrity is not None
                else None
            ),
        }


@dataclass(frozen=True)
class PasswordKeyMaterial:
    password_hash: bytes
    key_hash: bytes
    wrapping_key: bytes
    iv: bytes

    def to_json(self) -> dict[str, str]:
        return {
            "password_hash": self.password_hash.hex(),
            "key_hash": self.key_hash.hex(),
            "wrapping_key": self.wrapping_key.hex(),
            "iv": self.iv.hex(),
        }


@dataclass(frozen=True)
class UnwrappedSessionKey:
    stream_key: bytes
    stream_salt: bytes
    verifier_hash_input: bytes
    verifier_valid: bool

    def to_json(self) -> dict[str, object]:
        return {
            "stream_key": self.stream_key.hex(),
            "stream_salt": self.stream_salt.hex(),
            "verifier_hash_input": self.verifier_hash_input.hex(),
            "verifier_valid": self.verifier_valid,
        }


@dataclass(frozen=True)
class AgileDataIntegrityMaterial:
    hmac_key: bytes
    hmac_value: bytes

    def to_json(self) -> dict[str, str]:
        return {
            "hmac_key": self.hmac_key.hex(),
            "hmac_value": self.hmac_value.hex(),
        }


@dataclass(frozen=True)
class CryptSessionPrefix:
    version: int
    compatibility_version: int
    crypto_type: int
    crypto_xml: bytes

    def to_json(self) -> dict[str, object]:
        result: dict[str, object] = {
            "version": self.version,
            "compatibility_version": self.compatibility_version,
            "crypto_type": self.crypto_type,
            "crypto_xml_size": len(self.crypto_xml),
            "crypto_xml_sha256": hashlib.sha256(self.crypto_xml).hexdigest(),
        }
        try:
            result["descriptor"] = parse_crypto_xml(self.crypto_xml).to_json()
        except ValueError as error:
            result["descriptor_error"] = str(error)
        return result


def compute_password_hash(
    secret_utf16le: bytes,
    salt: bytes,
    *,
    spin_count: int,
    counter_after_hash: bool = False,
) -> bytes:


    if spin_count < 0 or spin_count > 0xFFFFFFFF:
        raise ValueError("spin_count must fit uint32")
    digest = hashlib.sha512(salt + secret_utf16le).digest()
    for counter in range(spin_count):
        encoded = counter.to_bytes(4, "little")
        digest = hashlib.sha512(
            digest + encoded if counter_after_hash else encoded + digest
        ).digest()
    return digest


def derive_key_from_password_hash(
    password_hash: bytes,
    *,
    block_key: bytes,
    key_bytes: int,
) -> tuple[bytes, bytes]:


    if key_bytes <= 0:
        raise ValueError("key_bytes must be positive")
    key_hash = hashlib.sha512(password_hash + block_key).digest()
    material = key_hash
    if key_bytes > len(material):
        material += b"\x36" * (key_bytes - len(material))
    return key_hash, material[:key_bytes]


def make_native_iv(salt: bytes, block_size: int) -> bytes:


    if block_size <= 0:
        raise ValueError("block_size must be positive")
    if len(salt) >= block_size:
        return salt[:block_size]
    return salt + b"\x36" * (block_size - len(salt))


def derive_key_manager_iv(
    stream_salt: bytes,
    block_key: bytes,
    block_size: int = CURRENT_BLOCK_BYTES,
) -> bytes:


    digest = hashlib.sha512(stream_salt + block_key).digest()
    return make_native_iv(digest, block_size)


def reset_block_key(first: int, second: int) -> bytes:


    for label, value in (("first", first), ("second", second)):
        if value < 0 or value > 0xFFFFFFFF:
            raise ValueError(f"{label} reset value must fit uint32")
    if second == 0:
        return struct.pack("<I", first)
    return struct.pack("<II", first, second)


def content_block_key(footer_salt: int, shard_index: int) -> bytes:


    return reset_block_key(footer_salt, shard_index)


def hmac_key_block_key(shard_index: int) -> bytes:


    return reset_block_key(HMAC_KEY_RESET_TAG, shard_index)


def hmac_value_block_key(shard_index: int) -> bytes:


    return reset_block_key(POST_HMAC_RESET_TAG, shard_index)


def derive_password_key_material(
    secret_utf16le: bytes,
    parameters: PasswordEncryptor,
    block_key: bytes,
) -> PasswordKeyMaterial:


    common = parameters.parameters
    _require_current_algorithms(common, "password encryptor")
    password_hash = compute_password_hash(
        secret_utf16le,
        common.salt,
        spin_count=parameters.spin_count,
    )
    key_hash, wrapping_key = derive_key_from_password_hash(
        password_hash,
        block_key=block_key,
        key_bytes=common.key_bits // 8,
    )
    return PasswordKeyMaterial(
        password_hash,
        key_hash,
        wrapping_key,
        make_native_iv(common.salt, common.block_size),
    )


def parse_crypt_session_prefix(data: bytes, *, strict_current: bool = True) -> CryptSessionPrefix:


    if len(data) < _SESSION_PREFIX.size:
        raise ValueError("truncated crypt-session prefix")
    version, compatibility_version, crypto_type = _SESSION_PREFIX.unpack_from(data)
    if strict_current:
        expected = (
            CURRENT_SESSION_VERSION,
            CURRENT_COMPAT_VERSION,
            CURRENT_CRYPTO_TYPE,
        )
        if (version, compatibility_version, crypto_type) != expected:
            raise ValueError(
                "unsupported crypt-session prefix: "
                f"got {(version, compatibility_version, hex(crypto_type))}, "
                f"expected {(expected[0], expected[1], hex(expected[2]))}"
            )
    return CryptSessionPrefix(
        version,
        compatibility_version,
        crypto_type,
        data[_SESSION_PREFIX.size :],
    )


def build_crypt_session_prefix(crypto_xml: bytes) -> bytes:


    return _SESSION_PREFIX.pack(
        CURRENT_SESSION_VERSION,
        CURRENT_COMPAT_VERSION,
        CURRENT_CRYPTO_TYPE,
    ) + bytes(crypto_xml)


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _required_attribute(element: ET.Element, name: str) -> str:
    value = element.get(name)
    if value is None:
        raise ValueError(f"{_local_name(element.tag)} is missing {name}")
    return value


def _unsigned_attribute(element: ET.Element, name: str) -> int:
    text = _required_attribute(element, name)
    try:
        value = int(text, 10)
    except ValueError as error:
        raise ValueError(f"invalid decimal {name}: {text!r}") from error
    if not 0 <= value <= 0xFFFFFFFF:
        raise ValueError(f"{name} does not fit uint32")
    return value


def _base64_attribute(element: ET.Element, name: str) -> bytes:
    text = _required_attribute(element, name)
    try:
        return base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError) as error:
        raise ValueError(f"invalid base64 {name}") from error


def _parse_common_parameters(element: ET.Element) -> EncryptionParameters:
    salt = _base64_attribute(element, "saltValue")
    result = EncryptionParameters(
        salt=salt,
        salt_size=_unsigned_attribute(element, "saltSize"),
        block_size=_unsigned_attribute(element, "blockSize"),
        key_bits=_unsigned_attribute(element, "keyBits"),
        hash_size=_unsigned_attribute(element, "hashSize"),
        cipher_algorithm=_required_attribute(element, "cipherAlgorithm"),
        cipher_chaining=_required_attribute(element, "cipherChaining"),
        hash_algorithm=_required_attribute(element, "hashAlgorithm"),
    )
    if len(result.salt) != result.salt_size:
        raise ValueError(
            f"saltValue has {len(result.salt)} bytes, expected {result.salt_size}"
        )
    return result


def parse_crypto_xml(data: bytes) -> CryptSessionDescriptor:


    try:
        root = ET.fromstring(data)
    except ET.ParseError as error:
        raise ValueError(f"invalid Crypto XML: {error}") from error
    if _local_name(root.tag) != "encryption":
        raise ValueError(f"unexpected Crypto XML root {_local_name(root.tag)!r}")

    key_data_element = next(
        (element for element in root.iter() if _local_name(element.tag) == "keyData"),
        None,
    )
    password_element = next(
        (
            element
            for element in root.iter()
            if _local_name(element.tag) == "encryptedKey"
            and element.get("spinCount") is not None
        ),
        None,
    )
    data_integrity_element = next(
        (
            element
            for element in root.iter()
            if _local_name(element.tag) == "dataIntegrity"
        ),
        None,
    )
    if key_data_element is None:
        raise ValueError("Crypto XML has no keyData element")
    if password_element is None:
        raise ValueError("Crypto XML has no password encryptedKey element")

    password = PasswordEncryptor(
        parameters=_parse_common_parameters(password_element),
        spin_count=_unsigned_attribute(password_element, "spinCount"),
        encrypted_verifier_hash_input=_base64_attribute(
            password_element, "encryptedVerifierHashInput"
        ),
        encrypted_verifier_hash_value=_base64_attribute(
            password_element, "encryptedVerifierHashValue"
        ),
        encrypted_key_value=_base64_attribute(password_element, "encryptedKeyValue"),
    )
    data_integrity = (
        AgileDataIntegrity(
            encrypted_hmac_key=_base64_attribute(
                data_integrity_element, "encryptedHmacKey"
            ),
            encrypted_hmac_value=_base64_attribute(
                data_integrity_element, "encryptedHmacValue"
            ),
        )
        if data_integrity_element is not None
        else None
    )
    return CryptSessionDescriptor(
        _parse_common_parameters(key_data_element),
        password,
        data_integrity,
    )


def _require_current_algorithms(parameters: EncryptionParameters, label: str) -> None:
    expected = (
        CURRENT_CRYPTO_ALGORITHM,
        CURRENT_CHAINING_MODE,
        CURRENT_HASH_ALGORITHM,
    )
    actual = (
        parameters.cipher_algorithm,
        parameters.cipher_chaining,
        parameters.hash_algorithm,
    )
    if actual != expected:
        raise ValueError(f"unsupported {label} algorithms {actual!r}")
    if parameters.block_size != CURRENT_BLOCK_BYTES:
        raise ValueError(f"unsupported {label} block size {parameters.block_size}")
    if parameters.hash_size != CURRENT_HASH_BYTES:
        raise ValueError(f"unsupported {label} hash size {parameters.hash_size}")
    if parameters.key_bits not in (128, 192, 256):
        raise ValueError(f"unsupported {label} AES key size {parameters.key_bits}")


def unwrap_stream_key(
    secret_utf16le: bytes,
    descriptor: CryptSessionDescriptor,
    *,
    require_valid_verifier: bool = True,
) -> UnwrappedSessionKey:


    if len(secret_utf16le) != CURRENT_SECRET_BYTES:
        raise ValueError(
            f"current secret must be {CURRENT_SECRET_BYTES} bytes "
            f"({CURRENT_SECRET_CODE_UNITS} UTF-16 code units)"
        )
    _require_current_algorithms(descriptor.key_data, "keyData")
    password = descriptor.password_encryptor
    _require_current_algorithms(password.parameters, "password encryptor")

    verifier_input_key = derive_password_key_material(
        secret_utf16le, password, ENCRYPTED_VERIFIER_INPUT_BLOCK_KEY
    )
    verifier_input_padded = decrypt_aligned(
        password.encrypted_verifier_hash_input,
        verifier_input_key.wrapping_key,
        verifier_input_key.iv,
    )
    verifier_input = verifier_input_padded[: password.parameters.salt_size]

    verifier_hash_key = derive_password_key_material(
        secret_utf16le, password, ENCRYPTED_VERIFIER_HASH_BLOCK_KEY
    )
    verifier_hash_padded = decrypt_aligned(
        password.encrypted_verifier_hash_value,
        verifier_hash_key.wrapping_key,
        verifier_hash_key.iv,
    )
    expected_hash = hashlib.sha512(verifier_input).digest()
    verifier_valid = hmac.compare_digest(
        verifier_hash_padded[: password.parameters.hash_size],
        expected_hash[: password.parameters.hash_size],
    )
    if require_valid_verifier and not verifier_valid:
        raise ValueError("vault secret does not match the password verifier")

    encrypted_key_material = derive_password_key_material(
        secret_utf16le, password, ENCRYPTED_KEY_VALUE_BLOCK_KEY
    )
    stream_key_padded = decrypt_aligned(
        password.encrypted_key_value,
        encrypted_key_material.wrapping_key,
        encrypted_key_material.iv,
    )
    stream_key_size = descriptor.key_data.key_bits // 8
    if len(stream_key_padded) < stream_key_size:
        raise ValueError("encryptedKeyValue is shorter than the stream key")
    return UnwrappedSessionKey(
        stream_key=stream_key_padded[:stream_key_size],
        stream_salt=descriptor.key_data.salt,
        verifier_hash_input=verifier_input,
        verifier_valid=verifier_valid,
    )


def decrypt_agile_data_integrity(
    stream_key: bytes,
    descriptor: CryptSessionDescriptor,
) -> AgileDataIntegrityMaterial:


    _require_current_algorithms(descriptor.key_data, "keyData")
    encrypted = descriptor.data_integrity
    if encrypted is None:
        raise ValueError("Crypto XML has no dataIntegrity element")
    block_size = descriptor.key_data.block_size
    hash_size = descriptor.key_data.hash_size
    for label, value in (
        ("encryptedHmacKey", encrypted.encrypted_hmac_key),
        ("encryptedHmacValue", encrypted.encrypted_hmac_value),
    ):
        if len(value) < hash_size or len(value) % block_size:
            raise ValueError(
                f"{label} must be block-aligned and at least {hash_size} bytes"
            )
    hmac_key = decrypt_aligned(
        encrypted.encrypted_hmac_key,
        stream_key,
        derive_key_manager_iv(
            descriptor.key_data.salt,
            AGILE_ENCRYPTED_HMAC_KEY_BLOCK_KEY,
            block_size,
        ),
    )[:hash_size]
    hmac_value = decrypt_aligned(
        encrypted.encrypted_hmac_value,
        stream_key,
        derive_key_manager_iv(
            descriptor.key_data.salt,
            AGILE_ENCRYPTED_HMAC_VALUE_BLOCK_KEY,
            block_size,
        ),
    )[:hash_size]
    return AgileDataIntegrityMaterial(hmac_key, hmac_value)


def verify_agile_data_integrity(
    encrypted_package: bytes,
    material: AgileDataIntegrityMaterial,
) -> bool:


    expected = hmac.new(material.hmac_key, encrypted_package, hashlib.sha512).digest()
    return hmac.compare_digest(expected, material.hmac_value)


def _aes_cbc(data: bytes, key: bytes, iv: bytes, *, decrypt: bool) -> bytes:
    if len(key) not in (16, 24, 32):
        raise ValueError("AES key must be 16, 24, or 32 bytes")
    if len(iv) != CURRENT_BLOCK_BYTES:
        raise ValueError("AES-CBC IV must be 16 bytes")
    if len(data) % CURRENT_BLOCK_BYTES:
        raise ValueError("native CNG path requires block-aligned input")
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    except ImportError as error:
        raise RuntimeError("AES operations require the 'cryptography' package") from error
    context = Cipher(algorithms.AES(key), modes.CBC(iv))
    worker = context.decryptor() if decrypt else context.encryptor()
    return worker.update(data) + worker.finalize()


def encrypt_aligned(plaintext: bytes, key: bytes, iv: bytes) -> bytes:


    return _aes_cbc(plaintext, key, iv, decrypt=False)


def decrypt_aligned(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:


    return _aes_cbc(ciphertext, key, iv, decrypt=True)


def _parse_hex(value: str, label: str) -> bytes:
    try:
        return bytes.fromhex(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError(f"invalid {label} hex: {error}") from error


def _cmd_inspect(args: argparse.Namespace) -> int:
    parsed = parse_crypt_session_prefix(
        Path(args.input).read_bytes(), strict_current=not args.relaxed
    )
    print(json.dumps(parsed.to_json(), indent=2, ensure_ascii=False))
    return 0


def _cmd_unwrap(args: argparse.Namespace) -> int:
    prefix = parse_crypt_session_prefix(Path(args.session).read_bytes())
    descriptor = parse_crypto_xml(prefix.crypto_xml)
    unwrapped = unwrap_stream_key(
        _parse_hex(args.secret_hex, "secret"), descriptor
    )
    print(json.dumps(unwrapped.to_json(), indent=2))
    return 0


def _cmd_transform(args: argparse.Namespace, *, decrypt: bool) -> int:
    key = _parse_hex(args.key_hex, "key")
    iv = _parse_hex(args.iv_hex, "IV")
    source = Path(args.input).read_bytes()
    result = (
        decrypt_aligned(source, key, iv)
        if decrypt
        else encrypt_aligned(source, key, iv)
    )
    Path(args.output).write_bytes(result)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    inspect = subparsers.add_parser(
        "inspect", help="inspect the Agile 4.4 header and Crypto XML"
    )
    inspect.add_argument("input")
    inspect.add_argument("--relaxed", action="store_true")
    inspect.set_defaults(func=_cmd_inspect)

    unwrap = subparsers.add_parser(
        "unwrap", help="verify a vault secret and unwrap the random stream key"
    )
    unwrap.add_argument("session")
    unwrap.add_argument("--secret-hex", required=True)
    unwrap.set_defaults(func=_cmd_unwrap)

    for name, is_decrypt in (("encrypt", False), ("decrypt", True)):
        transform = subparsers.add_parser(name, help=f"{name} block-aligned bytes")
        transform.add_argument("input")
        transform.add_argument("output")
        transform.add_argument("--key-hex", required=True)
        transform.add_argument("--iv-hex", required=True)
        transform.set_defaults(
            func=lambda args, decrypt=is_decrypt: _cmd_transform(args, decrypt=decrypt)
        )

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
