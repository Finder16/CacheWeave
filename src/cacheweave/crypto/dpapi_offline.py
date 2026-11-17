


from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import struct
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

CALG_SHA1 = 0x8004
CALG_HMAC = 0x8009
CALG_SHA_256 = 0x800C
CALG_SHA_512 = 0x800E
CALG_3DES = 0x6603
CALG_AES_256 = 0x6610

DPAPI_PROVIDER = uuid.UUID("df9d8cd0-1501-11d1-8c7a-00c04fc297eb")
BOOT_KEY_PERMUTATION = (8, 5, 4, 2, 11, 9, 13, 3, 0, 6, 1, 12, 14, 10, 15, 7)


class DpapiError(ValueError):
    pass


def _hash_module(alg: int):
    if alg in (CALG_SHA1, CALG_HMAC):
        return hashlib.sha1
    if alg == CALG_SHA_256:
        return hashlib.sha256
    if alg == CALG_SHA_512:
        return hashlib.sha512
    raise DpapiError(f"unsupported hash algorithm 0x{alg:x}")


def _cipher_params(alg: int) -> tuple[int, int]:
    if alg == CALG_AES_256:
        return 32, 16
    if alg == CALG_3DES:
        return 24, 8
    raise DpapiError(f"unsupported cipher algorithm 0x{alg:x}")


def _cbc_decrypt(alg: int, key: bytes, iv: bytes, data: bytes) -> bytes:
    if alg == CALG_AES_256:
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    elif alg == CALG_3DES:
        from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES

        cipher = Cipher(TripleDES(key), modes.CBC(iv))
    else:
        raise DpapiError(f"unsupported cipher algorithm 0x{alg:x}")
    decryptor = cipher.decryptor()
    return decryptor.update(data) + decryptor.finalize()






class RegHive:


    def __init__(self, data: bytes) -> None:
        if data[:4] != b"regf":
            raise DpapiError("not a registry hive (missing regf signature)")
        self.data = data
        self.minor = struct.unpack_from("<I", data, 24)[0]
        self.root = struct.unpack_from("<I", data, 36)[0]

    def _cell(self, offset: int) -> bytes:
        absolute = 0x1000 + offset
        if absolute + 4 > len(self.data):
            raise DpapiError(f"cell offset 0x{offset:x} outside hive")
        size = struct.unpack_from("<i", self.data, absolute)[0]
        length = -size if size < 0 else size
        return self.data[absolute + 4 : absolute + length]

    def _key_record(self, offset: int) -> dict:
        cell = self._cell(offset)
        if cell[:2] != b"nk":
            raise DpapiError(f"expected nk record at 0x{offset:x}")
        flags = struct.unpack_from("<H", cell, 2)[0]
        name_len, class_len = struct.unpack_from("<HH", cell, 72)
        raw_name = cell[76 : 76 + name_len]
        name = raw_name.decode("latin-1") if flags & 0x20 else raw_name.decode("utf-16-le")
        return {
            "name": name,
            "subkey_count": struct.unpack_from("<I", cell, 20)[0],
            "subkey_list": struct.unpack_from("<I", cell, 28)[0],
            "value_count": struct.unpack_from("<I", cell, 36)[0],
            "value_list": struct.unpack_from("<I", cell, 40)[0],
            "class_offset": struct.unpack_from("<I", cell, 48)[0],
            "class_len": class_len,
        }

    def _subkey_offsets(self, list_offset: int) -> Iterable[int]:
        cell = self._cell(list_offset)
        signature = cell[:2]
        count = struct.unpack_from("<H", cell, 2)[0]
        if signature in (b"lf", b"lh"):
            for index in range(count):
                yield struct.unpack_from("<I", cell, 4 + index * 8)[0]
        elif signature == b"li":
            for index in range(count):
                yield struct.unpack_from("<I", cell, 4 + index * 4)[0]
        elif signature == b"ri":
            for index in range(count):
                yield from self._subkey_offsets(struct.unpack_from("<I", cell, 4 + index * 4)[0])
        else:
            raise DpapiError(f"unknown subkey list signature {signature!r}")

    def subkeys(self, offset: int) -> dict[str, int]:
        record = self._key_record(offset)
        if not record["subkey_count"] or record["subkey_list"] == 0xFFFFFFFF:
            return {}
        return {
            self._key_record(child)["name"].lower(): child
            for child in self._subkey_offsets(record["subkey_list"])
        }

    def find(self, path: str) -> int:
        offset = self.root
        for part in [p for p in path.replace("/", "\\").split("\\") if p]:
            children = self.subkeys(offset)
            if part.lower() not in children:
                raise KeyError(path)
            offset = children[part.lower()]
        return offset

    def class_name(self, path: str) -> str:
        record = self._key_record(self.find(path))
        if record["class_offset"] == 0xFFFFFFFF or not record["class_len"]:
            return ""
        return self._cell(record["class_offset"])[: record["class_len"]].decode("utf-16-le")

    def values(self, path: str) -> dict[str, tuple[int, bytes]]:
        record = self._key_record(self.find(path))
        result: dict[str, tuple[int, bytes]] = {}
        if not record["value_count"] or record["value_list"] == 0xFFFFFFFF:
            return result
        offsets = self._cell(record["value_list"])
        for index in range(record["value_count"]):
            vk = self._cell(struct.unpack_from("<I", offsets, index * 4)[0])
            if vk[:2] != b"vk":
                raise DpapiError("expected vk record")
            name_len, size, data_offset, value_type, flags = struct.unpack_from("<HIIIH", vk, 2)
            raw = vk[20 : 20 + name_len]
            name = raw.decode("latin-1") if flags & 0x1 else raw.decode("utf-16-le")
            if size & 0x80000000:
                length = size & 0x7FFFFFFF
                data = struct.pack("<I", data_offset)[:length]
            else:
                data = self._value_data(data_offset, size)
            result[name.lower()] = (value_type, data)
        return result

    def _value_data(self, offset: int, size: int) -> bytes:
        cell = self._cell(offset)
        if cell[:2] == b"db" and size > 16344 and self.minor > 3:
            count, list_offset = struct.unpack_from("<HI", cell, 2)
            segments = self._cell(list_offset)
            data = b"".join(
                self._cell(struct.unpack_from("<I", segments, i * 4)[0])[:16344]
                for i in range(count)
            )
            return data[:size]
        return cell[:size]

    def value(self, path: str, name: str = "") -> bytes:
        values = self.values(path)
        if name.lower() not in values:
            raise KeyError(f"{path}\\{name}")
        return values[name.lower()][1]






def boot_key(system: RegHive) -> bytes:
    current = struct.unpack("<I", system.value("Select", "Current")[:4])[0]
    lsa = f"ControlSet{current:03d}\\Control\\Lsa"
    scrambled = bytes.fromhex("".join(system.class_name(f"{lsa}\\{n}") for n in ("JD", "Skew1", "GBG", "Data")))
    if len(scrambled) != 16:
        raise DpapiError("boot key class names do not form 16 bytes")
    return bytes(scrambled[i] for i in BOOT_KEY_PERMUTATION)


def _aes_ecb_blocks(key: bytes, data: bytes) -> bytes:
    data = data + bytes(-len(data) % 16)
    decryptor = Cipher(algorithms.AES(key), modes.ECB()).decryptor()
    return decryptor.update(data) + decryptor.finalize()


def _decrypt_lsa_secret(key: bytes, value: bytes) -> bytes:


    if len(value) < 28 + 32:
        raise DpapiError("LSA secret too short")
    encrypted = value[28:]
    digest = hashlib.sha256(key)
    for _ in range(1000):
        digest.update(encrypted[:32])
    plain = _aes_ecb_blocks(digest.digest(), encrypted[32:])
    length = struct.unpack_from("<I", plain, 0)[0]
    if 16 + length > len(plain):
        raise DpapiError("LSA secret blob length is inconsistent (wrong key?)")
    return plain[16 : 16 + length]


def lsa_key(security: RegHive, bootkey: bytes) -> bytes:
    secret = _decrypt_lsa_secret(bootkey, security.value("Policy\\PolEKList", ""))
    if len(secret) < 52 + 32:
        raise DpapiError("PolEKList secret too short")
    return secret[52:84]


@dataclass(frozen=True)
class DpapiSystemKey:
    version: int
    machine_key: bytes
    user_key: bytes
    source: str


def dpapi_system_keys(system: RegHive, security: RegHive) -> list[DpapiSystemKey]:
    key = lsa_key(security, boot_key(system))
    keys = []
    for name in ("CurrVal", "OldVal"):
        try:
            raw = security.value(f"Policy\\Secrets\\DPAPI_SYSTEM\\{name}", "")
        except KeyError:
            continue
        secret = _decrypt_lsa_secret(key, raw)
        if len(secret) < 44:
            continue
        version = struct.unpack_from("<I", secret, 0)[0]
        keys.append(DpapiSystemKey(version, secret[4:24], secret[24:44], name))
    if not keys:
        raise DpapiError("DPAPI_SYSTEM secret not found")
    return keys






def pbkdf2_hmac_variant(hash_fn, password: bytes, salt: bytes, length: int, rounds: int, dpapi_internal: bool) -> bytes:


    out = b""
    block = 1
    while len(out) < length:
        u = hmac.new(password, salt + struct.pack(">I", block), hash_fn).digest()
        acc = bytearray(u)
        for _ in range(rounds - 1):
            u = hmac.new(password, bytes(acc) if dpapi_internal else u, hash_fn).digest()
            for i, b in enumerate(u):
                acc[i] ^= b
        out += bytes(acc)
        block += 1
    return out[:length]


@dataclass(frozen=True)
class MasterKeyFile:
    guid: str
    version: int
    flags: int
    master_key: bytes
    backup_key: bytes


def parse_master_key_file(data: bytes) -> MasterKeyFile:
    if len(data) < 128:
        raise DpapiError("master key file too short")
    version = struct.unpack_from("<I", data, 0)[0]
    guid = data[12:84].decode("utf-16-le").rstrip("\x00")
    flags = struct.unpack_from("<I", data, 92)[0]
    mk_len, bk_len, ch_len, dk_len = struct.unpack_from("<QQQQ", data, 96)
    if 128 + mk_len + bk_len + ch_len + dk_len != len(data):
        raise DpapiError("master key file section lengths do not match file size")
    return MasterKeyFile(guid, version, flags, data[128 : 128 + mk_len], data[128 + mk_len : 128 + mk_len + bk_len])


def decrypt_master_key(record: bytes, key: bytes) -> tuple[bytes, str] | None:


    salt = record[4:20]
    rounds, hash_alg, crypt_alg = struct.unpack_from("<III", record, 20)
    encrypted = record[32:]
    hash_fn = _hash_module(CALG_SHA1 if hash_alg == CALG_HMAC else hash_alg)
    key_len, iv_len = _cipher_params(crypt_alg)
    digest_len = hash_fn().digest_size
    for variant in (True, False):
        derived = pbkdf2_hmac_variant(hash_fn, key, salt, key_len + iv_len, rounds, variant)
        plain = _cbc_decrypt(crypt_alg, derived[:key_len], derived[key_len:], encrypted)
        hmac_salt = plain[:16]
        stored_hmac = plain[16 : 16 + digest_len]
        master_key = plain[-64:]
        hmac_key = hmac.new(key, hmac_salt, hash_fn).digest()
        if hmac.compare_digest(hmac.new(hmac_key, master_key, hash_fn).digest(), stored_hmac):
            return master_key, "dpapi_internal" if variant else "standard"
    return None






@dataclass(frozen=True)
class DpapiBlob:
    raw: bytes
    master_key_guid: str
    flags: int
    description: str
    crypt_alg: int
    salt: bytes
    hash_alg: int
    hmac_key: bytes
    data: bytes
    sign: bytes


def parse_dpapi_blob(raw: bytes) -> DpapiBlob:
    pos = 0

    def u32() -> int:
        nonlocal pos
        value = struct.unpack_from("<I", raw, pos)[0]
        pos += 4
        return value

    def take(n: int) -> bytes:
        nonlocal pos
        if pos + n > len(raw):
            raise DpapiError("truncated DPAPI blob")
        value = raw[pos : pos + n]
        pos += n
        return value

    u32()
    if uuid.UUID(bytes_le=take(16)) != DPAPI_PROVIDER:
        raise DpapiError("not a DPAPI blob (provider GUID)")
    u32()
    mk_guid = str(uuid.UUID(bytes_le=take(16)))
    flags = u32()
    description = take(u32()).decode("utf-16-le", "replace").rstrip("\x00")
    crypt_alg = u32()
    u32()
    salt = take(u32())
    take(u32())
    hash_alg = u32()
    u32()
    hmac_key = take(u32())
    data = take(u32())
    sign = take(u32())
    if pos != len(raw):
        raise DpapiError(f"DPAPI blob has {len(raw) - pos} trailing bytes")
    return DpapiBlob(raw, mk_guid, flags, description, crypt_alg, salt, hash_alg, hmac_key, data, sign)


def decrypt_dpapi_blob(blob: DpapiBlob, master_key: bytes, entropy: bytes | None = None) -> bytes | None:
    hash_fn = _hash_module(blob.hash_alg)
    key_hash = hashlib.sha1(master_key).digest()
    session = hmac.new(key_hash, blob.salt + (entropy or b""), hash_fn).digest()
    block_size = hash_fn().block_size
    key_len, iv_len = _cipher_params(blob.crypt_alg)
    derived = session
    if len(derived) > block_size:
        derived = hmac.new(derived, b"", hash_fn).digest()
    if len(derived) < key_len:
        padded = derived + bytes(block_size)
        ipad = bytes(b ^ 0x36 for b in padded[:block_size])
        opad = bytes(b ^ 0x5C for b in padded[:block_size])
        derived = hash_fn(ipad).digest() + hash_fn(opad).digest()
    plain = _cbc_decrypt(blob.crypt_alg, derived[:key_len], bytes(iv_len), blob.data)
    pad = plain[-1]
    if not 1 <= pad <= iv_len or plain[-pad:] != bytes([pad]) * pad:
        return None
    plain = plain[:-pad]
    to_sign = blob.raw[20 : len(blob.raw) - len(blob.sign) - 4]
    candidates = []
    padded = key_hash + bytes(block_size)
    ipad = bytes(b ^ 0x36 for b in padded[:block_size])
    opad = bytes(b ^ 0x5C for b in padded[:block_size])
    inner = hash_fn(ipad + blob.hmac_key).digest()
    outer = hash_fn(opad + inner + (entropy or b"") + to_sign).digest()
    candidates.append(outer)
    candidates.append(hmac.new(key_hash, blob.hmac_key + (entropy or b"") + to_sign, hash_fn).digest())
    if not any(hmac.compare_digest(c, blob.sign) for c in candidates):
        return None
    return plain






class OfflineMachineDpapi:


    def __init__(self, system_hive: Path, security_hive: Path, master_key_dir: Path) -> None:
        self.system_keys = dpapi_system_keys(
            RegHive(system_hive.read_bytes()), RegHive(security_hive.read_bytes())
        )
        self.master_key_dir = master_key_dir
        self._cache: dict[str, bytes] = {}
        self.log: list[dict[str, str]] = []

    @classmethod
    def from_windows_root(cls, root: Path) -> "OfflineMachineDpapi":
        system32 = root / "Windows" / "System32"
        return cls(
            system32 / "config" / "SYSTEM",
            system32 / "config" / "SECURITY",
            system32 / "Microsoft" / "Protect" / "S-1-5-18",
        )

    def master_key(self, guid: str) -> bytes:
        guid = guid.lower()
        if guid in self._cache:
            return self._cache[guid]
        for directory in (self.master_key_dir, self.master_key_dir / "User"):
            path = directory / guid
            if not path.is_file():
                continue
            mk_file = parse_master_key_file(path.read_bytes())
            for system_key in self.system_keys:
                for label, pre_key in (("machine", system_key.machine_key), ("user", system_key.user_key)):
                    result = decrypt_master_key(mk_file.master_key, pre_key)
                    if result is not None:
                        self._cache[guid] = result[0]
                        self.log.append(
                            {
                                "master_key": guid,
                                "directory": directory.name,
                                "dpapi_system": f"{system_key.source}.{label}",
                                "pbkdf2": result[1],
                            }
                        )
                        return result[0]
        raise DpapiError(f"master key {guid} not found or not decryptable")

    def unprotect(self, raw_blob: bytes, entropy: bytes | None = None) -> bytes:
        blob = parse_dpapi_blob(raw_blob)
        plain = decrypt_dpapi_blob(blob, self.master_key(blob.master_key_guid), entropy)
        if plain is None:
            raise DpapiError("DPAPI blob signature did not verify")
        return plain


def main() -> int:
    parser = argparse.ArgumentParser(description="decrypt a machine-scope DPAPI blob offline")
    parser.add_argument("--system", type=Path, required=True)
    parser.add_argument("--security", type=Path, required=True)
    parser.add_argument("--master-key-dir", type=Path, required=True)
    parser.add_argument("blob", type=Path)
    parser.add_argument("--output", type=Path, required=True,
                        help="new file for the plaintext (for a vault blob: key material); an existing file is never overwritten")
    args = parser.parse_args()
    if args.output.exists():
        parser.error(f"--output {args.output} exists; plaintext is written to a new file only")
    dpapi = OfflineMachineDpapi(args.system, args.security, args.master_key_dir)
    plaintext = dpapi.unprotect(args.blob.read_bytes())
    with open(args.output, "xb") as output:
        output.write(plaintext)
    print(json.dumps({"status": "ok", "log": dpapi.log}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
