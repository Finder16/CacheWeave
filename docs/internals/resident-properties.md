# DRG resident-property byte formats

This page records the resident-property byte grammar recovered from
`mso20win32client.dll` and `mso30win32client.dll` 16.0.20527.20196. The codecs
were checked against captured `.C4` values as well as the native read and write paths.

## Storage::Terse version 2

`Storage::Terse::Writer::BeginWriteHeader` (`mso20 +0xe4a00`),
`EndWriteHeader` (`+0xe48f8`), and `Reader::Verify` (`+0xe96a0`) establish the
complete v2 envelope:

```text
offset  size  field
0       1     version = 2
1       4     payload checksum, little-endian uint32
5       4     payload byte count, little-endian uint32
9       N     payload
```

The normal reader requires exactly `9 + payload_byte_count` bytes. Reader flag
bit `0x02` permits a larger backing buffer and limits the logical view to the
declared payload. Flag bit `0x01` is fragment mode and skips the v2 header
verification path. Version 1 is headerless.

The checksum routine is named `Storage::Crc32`, but it is not one of the common
IEEE/Castagnoli CRC-32 variants. It uses an MSB-first update, initial value 0,
no final XOR, and polynomial `0x000000af`:

```text
crc = 0
for byte in payload:
    crc = (crc << 8) ^ table[((crc >> 24) ^ byte) & 0xff]
    crc &= 0xffffffff
```

The 256-entry table begins `0000 00af 015e 01f1 ...` at
`mso20 +0x6cd1f0`. All entries match a generated width-32 MSB table for that
polynomial. The independent check vector `"123456789"` produces `0xbd0be338`.

Unsigned integers use ordinary ULEB128 (`Writer +0xe1c00` and `+0xe2010`).
Signed integers are ZigZag-transformed and then written as ULEB128 (`+0x518bf0`,
`+0x518c50`, and `+0x518c70`). A byte-vector in v2 is a ULEB128 element count
followed by raw bytes. A wide string is a ULEB128 UTF-16 code-unit count followed
by one ULEB128 value per code unit. GUIDs are 16 raw Windows `_GUID` bytes.

`src/cacheweave/formats/terse_codec.py` implements this envelope, checksum,
integer grammar, and strict bounds checks.

## DocumentMetadata

`GenerateDocumentMetadataResidentProperty` (`mso30 +0x1f55b8`) creates a v2
Terse writer. `ReadDocumentMetadataResidentProperty` (`+0x6bb64c`) performs the
inverse and requires exact payload EOF.

```text
ULEB16 stream_version
ULEB16 element_count
repeat element_count times:
    ULEB64 metadata_key
    if stream_version >= 6:
        ULEB64 value_type_id
    value encoded by type
```

Current type IDs are:

| ID | Logical type | Encoding |
|---:|---|---|
| 1 | `bool` | one byte, `00` or `01` |
| 2 | `vector<uint8_t>` | ULEB32 count, then raw bytes |
| 3 | `_GUID` | 16 raw bytes |
| 4 | `uint16_t` | ULEB16 |
| 5 | `uint32_t` | ULEB32 |
| 6 | `uint64_t` | ULEB64 |
| 7 | `std::wstring` | ULEB32 code-unit count, then ULEB16 units |

Versions below 6 omit the type ID and call `GetMetadataValueTypeId`
(`+0x1f78c8`) to infer it from the key and stream version. The current parser
rejects those older streams instead of applying a current-build key table to a
legacy payload.

## DocumentStorageRevisions

The current writer `GenerateRevisionsResidentProperty` (`mso30 +0x377188`)
uses `Storage::KeyValueTree`. `ReadRevisionsResidentProperty` (`+0x2de66c`)
tries KVTree first and falls back to the legacy Terse reader (`+0x2dbce4`) when
deserialization fails.

The outer KVTree serialization is:

```text
69                      magic byte
LZ4 Frame               standard LZ4F stream containing the KVTree payload
```

This is confirmed by `KVTreeImplementation::Serialize` (`mso20 +0x3a7a00`),
`KeyValueTree::Deserialize` (`+0x5113f0`), and direct calls to
`LZ4F_compressUpdate`/`LZ4F_decompress`. The decoded payload starts with a
ULEB32 root child count and then contains a pre-order node sequence.

Each node is:

```text
ULEB8  key_type
...    key bytes selected by key_type
ULEB8  serialized_value_tag
...    value bytes selected by normalized tag
if tag says subtree:
    ULEB32 direct_child_count
    ... direct children in pre-order
```

Key types are `0..11`: vectors of `u8/u16/u32/u64`, `array<u8,16>`, wide
string, narrow string, GUID, and scalar `u8/u16/u32/u64`. Vector and string
lengths are ULEB32. `vector<u8>` and narrow-string contents are raw bytes;
larger unsigned vector elements are individually ULEB-encoded. Wide strings
use ULEB16 code units. Fixed arrays and GUIDs are raw 16-byte values.

Logical value variant indices are:

| Index | Type | Index | Type |
|---:|---|---:|---|
| 0 | NotSet | 11 | `uint8_t` |
| 1 | bool | 12 | `uint16_t` |
| 2 | `vector<uint8_t>` | 13 | `uint32_t` |
| 3 | `vector<uint16_t>` | 14 | `uint64_t` |
| 4 | `vector<uint32_t>` | 15 | `int16_t` |
| 5 | `vector<uint64_t>` | 16 | `int32_t` |
| 6 | `vector<int16_t>` | 17 | `int64_t` |
| 7 | `vector<int32_t>` | 18 | narrow string |
| 8 | `vector<int64_t>` | 19 | wide string |
| 9 | `array<uint8_t,16>` | 20 | `Storage::Binary` |
| 10 | GUID | | |

The physical tag is more compact than the variant index:

- regular nonempty values normally use their variant index;
- adding `0x46` means the node also has a subtree;
- `0x15/0x16` encode true/false;
- `0x17..0x1a` encode empty unsigned vectors;
- `0x1c..0x1e` encode empty signed vectors;
- `0x20` is the zero GUID;
- `0x21..0x27` are zero scalar integers;
- `0x28/0x29` are empty narrow/wide strings;
- `0x70 + length` encodes a Binary value of 0 through `0x45` raw bytes;
- Binary tags `0xb6..0xfb` are the same lengths plus subtree (`+0x46`).

Unsigned values use ULEB128. Signed values and signed-vector elements use
ZigZag plus ULEB128. `src/cacheweave/formats/decode_kvtree.py` implements the LZ4 frame,
complete current key/value table, compact tags, subtree traversal, and strict
EOF/size/node/depth checks. `src/cacheweave/formats/decode_revisions.py` adds the
DocumentStorageRevisions schema, semantic names, producer-version unpacking,
duplicate/type validation, and a tolerant forensic mode for future schemas.

The revisions root currently contains:

| Root key (`uint16`) | Meaning |
|---:|---|
| 0 | revision-stream version |
| 1 | subtree of revision records |
| 2 | packed Office version: build in low 16 bits, revision in high 16 bits |

Root key 1 contains revision records keyed by a `uint32_t` storage revision ID.
Each record has a NotSet value plus a subtree keyed by `uint16_t` property ID.
The current schema is:

| Property | Value type | `RevisionData` offset | Recovered meaning |
|---:|---|---:|---|
| `0x00` | `vector<uint32_t>` | `+0x18` | parents |
| `0x01` | `vector<uint8_t>` | `+0x30` | labels |
| `0x02` | `vector<uint8_t>` | `+0x48` | host-known-version info |
| `0x03` | `vector<uint8_t>` | `+0x60` | remote revision ID |
| `0x04` | `vector<uint8_t>` | `+0x78` | application data |
| `0x05` | `array<uint8_t,16>` | `+0x1a0` | dictionary pile ID |
| `0x06` | `uint64_t` | `+0x90` | legacy local-save time |
| `0x07` | `vector<uint8_t>` | `+0xa0` | serialized `RevisionClockData` |
| `0x08` | `vector<uint8_t>` | external map | probability-vortex material |
| `0x09` | `vector<uint8_t>` | `+0xb8` | `RevisionMetadataKey::SyncToken` |
| `0x0a` | not emitted | -- | reserved/legacy in this build |
| `0x0b` | `vector<uint8_t>` | `+0xd0` | `RevisionMetadataKey::ClockData` |
| `0x0c` | `array<uint8_t,16>` | `+0x1c8` | ZipParts pile ID |
| `0x0d` | `array<uint8_t,16>` | `+0x1f0` | SingleBlob ID |
| `0x0e` | `array<uint8_t,16>` | `+0x208` | ZipPartsAdditional pile ID |
| `0x0f` | `vector<uint8_t>` | `+0xe8` | `RevisionMetadataKey::CobaltHostKnowledge` |
| `0x10` | `vector<uint8_t>` | `+0x100` | `RevisionMetadataKey::RevisionMetadataFlags` |
| `0x11` | `uint64_t` | `+0x118` | `RevisionMetadataKey::SizeInBytes` |
| `0x12` | `vector<uint8_t>` | `+0x120` | `RevisionMetadataKey::QuickXorHash` |
| `0x13` | `bool` | `+0x138` | `RevisionMetadataKey::IsDirtyFromHost` |
| `0x14` | `vector<uint8_t>` | `+0x150` | serialized `RevisionMetadataKey::LastOcsSave` |
| `0x15` | `vector<uint8_t>` | `+0x168` | `RevisionMetadataKey::ContainedInRemoteRevisionId` |
| `0x16` | narrow string | `+0x180` | `RevisionMetadataKey::OCSRevisionFormat` |
| `0x17` | `uint64_t` | `+0x140` | `RevisionMetadataKey::LocalFileLastModifiedTime` |

The map is established in both directions. The writer at `mso30 +0x377188`
maps offsets to numeric KVTree keys. `RevisionGraph::EnsureLoaded`
(`+0x2ebc00`) maps the same offsets into named `RevisionMetadataKey` entries or
builder fields. Its trace branches independently identify the four data-model
IDs as dictionary, ZipParts, SingleBlob, and ZipPartsAdditional. No live-value
guessing is used for these names.

Three byte-vector properties are fixed POD snapshots. `EnsureLoaded` rejects
any other size before copying them into their typed variants:

| Property | Typed variant | Required bytes |
|---:|---|---:|
| `0x09` | `SyncToken` | 24 |
| `0x0b` | `ClockData` | 36 |
| `0x10` | `RevisionMetadataFlags` | 8 |

Property `0x07` is a headerless Terse-v1 payload. The span constructor
`RevisionClockData::RevisionClockData` (`mso30 +0x1fc710`) creates a version-1
reader with flags zero, and `RevisionClockData::Flatten` (`+0x523978`) writes
the inverse representation:

```text
ULEB32 wchar_count
repeat wchar_count times:
    ULEB16 UTF-16 code unit
ULEB32 opaque_byte_count = 16
bytes  opaque_16
ULEB32 uint32_field
bytes  optional extension tail
```

The current constructor requires the middle vector to be exactly 16 bytes but
does not call `Reader::IsFinished`; extension bytes after the third field are
therefore valid and remain in the object's cached original byte vector. Field
types and offsets (`wstring +0x00`, 16 bytes at `+0x20`, `uint32_t +0x30`) are
confirmed, while their stripped source-level field names are not. The decoder
uses neutral names and preserves any tail instead of inventing semantics.

Property `0x14` is itself a complete Terse-v2 stream. The inverse routines
`SerializeLastOcsSave` (`mso30 +0x60e438`) and `DeserializeLastOcsSave`
(`+0x5d0d60`) establish its payload exactly:

```text
ULEB64 sequence_number
u8     ocs_match (strict bool 0 or 1)
ULEB32 ocs_session_id byte count
bytes  ocs_session_id (std::string)
EOF
```

`src/cacheweave/formats/decode_revisions.py` decodes the headerless RevisionClockData payload, checks
the fixed POD sizes, and recursively validates and names the nested
LastOcsSave stream.

## AuditLog

The third resident name is `AuditLog`. `WriteAuditLogResidentProperty`
(`mso30 +0x2e0258`) persists `AuditLog::SerializeAllTraces` (`+0x9ff450`), and
`ReadAuditLogResidentProperty` (`+0x3f6014`) passes the stored byte vector into
the deserializing `AuditLog` constructor (`+0x9fed04`). This is also a Terse v2
stream. Its payload is fixed as:

```text
ULEB8  audit_version = 1
ULEB64 ring_cursor (0..4095)
repeat exactly 4096 times:
    ULEB32 sequence_number
    ULEB32 process_id
    ULEB16 test_locus
    ULEB64 payload_word_0
    ULEB64 payload_word_1
```

`NotifyTestLocus` (`+0xa1ac7c`) uses the header value as an index into a
4096-entry ring and wraps it modulo `0x1000`. It stores an incrementing counter
as `sequence_number`, the current process ID, a `TestLocus` value, and copies a
16-byte event value into the final two words. `AppendDiagnosticsForTraces`
(`+0x9ff104`) independently confirms the process-ID and locus fields. The
16-byte event value remains opaque because its interpretation depends on the
locus. The fixed trace count follows both the serializer loop and constructor
loop. `src/cacheweave/formats/terse_codec.py` implements this grammar and emits a
combined `payload_hex`.

## Placement

The resident-property payload codecs are independent of the lower physical
container. Loose namespaces keep them in `.C4` cluster sets; the related Arx
superblock, allocator, file index, hash directory, buckets, and file records
are documented in `arx-container.md`. Namespace placement and object naming are
covered in `physical-storage.md`, while the optional encrypted-stream layer is
covered in `protected-storage.md`.
