# Arx physical-container format

This note records the byte-level Arx/Syzygy container structures recovered
from `mso20win32client.dll` 16.0.20527.20196. The findings are static but are
implemented in `src/cacheweave/formats/arx_codec.py` and checked on a live
volume: see "Live validation" below. The outer path is
`OfficeFileCache\0\0\<namespace>\0.ARX`. The physical Superblock placement is
fixed below.

## Layering and units

```text
physical volume
  superblock ZigZag root
    allocator ZigZag root
    file-index root
      legacy FileIndex: one LZ4 frame containing all files
      extendible FileIndex: HashDirectory ZigZag + KVTree buckets
        Bucket file records: Terse v2
```

`Storage::Extent` is always two little-endian uint64 byte values: absolute
offset and length. Allocator block-run lists are named for their role, not for
their units; the native verifier compares their values directly with byte
sizes. Allocator tree pointers, HashDirectory buckets, and persisted roots are
also byte-addressed. HashDirectory buckets must begin at or after `0x2000`;
both offset and length are 4-KiB aligned, and length is `0x1000..0x10000`.

## Storage::Compression

The monolithic FileIndex and NextGenAllocator use `Storage::Compression`, not
KVTree. It is a standard LZ4 Frame with no proprietary prefix or suffix:

- `Writer::BeginWriteHeader` at `+0x2c5c68` calls
  `LZ4F_compressBegin_internal`;
- `Writer::CompressAndWrite` at `+0x2c4130` calls `LZ4F_compressUpdate`;
- `Writer::EndWriteHeader` at `+0x2c2a3c` calls `LZ4F_compressEnd`;
- `Reader::EnsureDecompressionContext` at `+0x283340` calls
  `LZ4F_headerSize` and `LZ4F_getFrameInfo`;
- `Reader::DecompressAndRead` at `+0x283170` calls `LZ4F_decompress` and
  requires each typed read to produce its exact requested byte count.

Reader flag bit 0 requires both the LZ4 block-checksum and content-checksum
frame flags. The decoded primitive representation is raw little-endian. A
`vector<uint8>` is `uint32 byte_count` followed by the bytes. A `wstring` is
`uint32 UTF-16 code_unit_count` followed by raw UTF-16LE code units.

## Monolithic FileIndex

`FileIndex::Serialize` (`+0x47c910`) and its payload writer (`+0x589c40`)
produce this decoded LZ4 payload. `FileIndex::Deserialize` is at `+0x44f610`.

```text
u16 file_count
repeat file_count times:
    u32 name_code_units
    u16 name[name_code_units]               # raw UTF-16LE
    u16 extent_count
    repeat extent_count times:
        u64 extent_offset
        u64 extent_length
    u32 file_attributes
    u32 creation_time_low
    u32 creation_time_high
    u32 last_access_time_low
    u32 last_access_time_high
    u32 last_write_time_low
    u32 last_write_time_high
    u64 logical_file_size
```

The per-file routines are `File::SerializeInto` (`+0x3d2760`) and
`File::DeserializeFrom` (`+0x588fe0`). Deserialization rejects a record unless
the sum of all extent lengths equals `logical_file_size`.

## NextGenAllocator

`NextGenAllocator::Serialize` (`+0x46e220`) reaches the payload writer at
`+0x59e0bc`; the inverse is `NextGenAllocator::Deserialize` at `+0x437de0`.
The decoded version-1 LZ4 payload is:

```text
u64 format_version = 1
u64 allocator_generation
u64 pinned_file_index_generation
u64 pinned_file_index_root_offset
u64 pinned_file_index_root_length
u64 physical_volume_size_bytes
u8  freeze_active
u64 minimum_allocatable_byte_offset
u32 free_list_payload_size
u8  free_list_block_runs[free_list_payload_size]
u64 indirection_depth
u32 root_pointer_payload_size
u8  root_leaf_pointers[root_pointer_payload_size]
u32 frozen_list_payload_size
u8  frozen_list_block_runs[frozen_list_payload_size]
```

The generation field is independently confirmed by `GetGeneration`
(`+0x59eba0`), `IncrementGeneration` (`+0x59ebf0`), and `TryGetGeneration`
(`+0x59fe20`). The three pinned-file-index fields follow directly from
`PinFileIndex`. `AddNew(total, reserved)` establishes the total and minimum
allocatable block boundary.

`EncodeBlockRuns` (`+0x57c814`) writes `ULEB64 count`, then for each sorted
extent `ULEB64(offset - previous_end), ULEB64(length)`. The inverse is
`+0x57c6a4`. Office reverses the decoded free/frozen vectors for its in-memory
stack ordering; the serialized order is ascending physical order. Leaf
pointers (`+0x58ef48`/`+0x58edb8`) use `ULEB64 count` followed by absolute
`offset,length` pairs. These fields are byte extents, not block numbers:
`NextGenAllocator::Verify` (`+0x59fed0`) compares the serialized volume size,
minimum offset, free/frozen extent ends, and root pointers directly with byte
sizes. It requires the minimum offset to be at least `0x2000`. Root and
indirect tree pointers have the stronger predicate at `+0x59f024`: length
exactly `0x1000`, offset 4096-aligned, offset at or above the minimum, and the
whole block inside the serialized physical-volume size.

`NextGenAllocator::Load` (`+0x4699c0`) follows the root pointer vector through
`indirection_depth` pointer tiers. Every intermediate 4-KiB block contains the
length-prefixed `DecodeLeafPointerBlock` grammar; the final tier contains the
length-prefixed delta-coded free runs consumed by `DecodeLeaf`. Loaded leaf
runs must begin at or above the minimum byte offset and end inside the volume.
The loader also records all tree-block extents, appends the recovered leaf runs
to the in-memory free list, coalesces that list, and retains the tree blocks as
allocator metadata. `src/cacheweave/formats/arx_codec.py physical-volume` now reproduces this
walk and reports `tree_block_extents` plus `spilled_free_list`.

## Superblock

The superblock is a `Storage::KeyValueTree` (`0x69` plus an LZ4 Frame). Create,
deserialize, and verify are at `+0x5a2010`, `+0x5a2450`, and `+0x5a2950`.
All root keys are uint8:

| Key | Value | Type |
|---:|---|---|
| 0 | format version | uint64 |
| 1 | allocator version | uint64 |
| 2 | hash algorithm | uint8 |
| 3 | generation | uint64 |
| 4 | file-index version | uint64 |
| 5 | reserved block count | uint64 |
| 6 | feature flags | uint64 |
| 7 | allocator root extent | Binary[16] |
| 8 | file-index root extent | Binary[16] |
| 9 | volume ID | byte[16] |
| 10 | creation FILETIME | uint64 |

Defaults are versions/algorithm/generation/flags zero, reserved count 16,
allocator root `{2,1}`, file-index root `{3,1}`, a random 16-byte volume ID,
and current FILETIME. The two tiny default extents are creation-time
placeholders; the allocator/file-index persistence path replaces them before a
usable volume is mounted. Verification requires reserved count at least two
and no greater than `volume_size >> 12`; both root offsets are at least two and
their ends are compared directly with the physical byte size.

The root getter and setter functors were followed through their vtables. The
allocator path is `+0x5a2760 -> +0x5a1888` and the file-index path is
`+0x5a27a0 -> +0x5a1b38`; both copy the exact Binary[16] `Storage::Extent`
without shifting either qword. Their setters likewise write the exact 16 bytes
through `+0x5a2810 -> +0x5a1e94` and `+0x5a2820 -> +0x5a1f4c`. The roots are
therefore byte-addressed despite the historical `*RootBlock` member names.
`LogicalVolume::LoadAllocations` (`+0x5986dc`) separately rejects a zero or
non-4096-aligned allocator-root byte length.

## Fixed physical placement and mount

The outer Superblock placement no longer needs to be guessed from a specimen.
At `LogicalVolume::Open` call site `+0x599593`, Office passes the constant
extent stored at image RVA `0x7a3de0`:

```text
Storage::Extent superblock_root = { byte_offset: 0, byte_length: 0x2000 }
```

`ZigZag::ReadHalves` splits that exact range into two 0x1000-byte slots at
physical file offsets `0x0000` and `0x1000`. Each valid slot begins with the
Superblock KVTree byte `0x69` and one complete LZ4 Frame. `ZigZag::Save` writes
only the serialized bytes at the beginning of the parity-selected slot, so the
remaining bytes may be zero or stale and are outside the KVTree stream.
`ZigZag::SelectLatest` chooses the valid larger generation; its `<=` comparison
chooses slot 1 when two valid generations tie. A corrupt half can therefore be
recovered from the other half without a separate CRC wrapper.

After choosing the Superblock, mount requires the physical file size to be a
multiple of 0x1000 and at least `(reserved_block_count + 16) << 12`. It then
loads the allocator root followed by the file-index root/generation. The
next-generation allocator supplies its pinned FileIndex generation and root;
the legacy path takes them from the Superblock. `arx_codec.py
volume-superblocks <physical-volume>` now extracts the two fixed slots,
ignores post-frame slot padding, validates both Superblocks, and reproduces
Office's generation selection.

`Instance::Mount` (`+0x58ddd0`) caches logical volumes by the exact supplied
`Storage::Path`; it does not derive a hidden sibling filename in this layer.
`PhysicalVolume::BeginOpen` (`+0x5a0800`) opens that same path read/write with
access `0xc0000000`, share mode `3`, existing-file disposition `3`, and flags
`0x88000080`. `PhysicalVolume::Add` (`+0x5a0490`) uses create disposition `2`.
Mount flag bit 0 selects `LogicalVolume::Add`; otherwise bit 1 must be set and
selects `LogicalVolume::Open`.

`LogicalVolume` selects both backends through the same settings feature 3.
Helper `+0x59593c` creates `NextGenAllocator` when enabled and the legacy
allocator otherwise. Helper `+0x5951f0` creates `ExtendibleFileIndex` when
enabled and the monolithic `FileIndex` otherwise; settings integer 4 supplies
the extendible bucket cap, clamped to `0x10000`.

For the current next-generation path, the allocator root is itself a ZigZag
whose halves are standard LZ4-frame `NextGenAllocator` states. The latest
state's `pinned_file_index_generation` and `pinned_file_index_root` override
the Superblock file-index root. A monolithic root is one block-rounded extent
containing its LZ4 stream at the start. An extendible root is a HashDirectory
ZigZag; repeated directory slots are grouped by identical bucket byte extent,
and each unique extent contains one padded Bucket KVTree.

`decode_physical_volume` in `src/cacheweave/formats/arx_codec.py` implements that complete
current mount chain. It selects both Superblock and allocator generations,
uses the pinned FileIndex root, auto-detects monolithic versus extendible form,
and for the latter decodes every unique referenced Bucket. The synthetic test
suite covers both complete chains and the corrupt/unknown FileIndex case.

## ZigZag roots

`ZigZag::ReadHalves` (`+0x5a43e8`) requires a nonempty 4-KiB-aligned root
extent, splits it into equal halves, and attempts to deserialize each complete
half. `decode_and_validate_zigzag_half` (`+0x5a3974`) invokes the virtual
Deserialize/TryGetGeneration/Verify chain. `SelectLatest` (`+0x5a51e8`) selects
the valid highest generation. `Save` (`+0x5a4910`) writes the serialized bytes
at the start of the parity-selected half.

There is no generic persisted `{generation,size,crc}` wrapper around a ZigZag
half. `PayloadCrc32` in `trace_zigzag_generation_write` (`+0x5a3bf8`) and the
CRC calculated on invalid halves are diagnostic trace values only. Earlier
references to a transaction/free-list CRC were a misclassification of trace
and allocator code and must not be used as an on-disk-format claim.

## Extendible HashDirectory

`HashDirectory::Serialize`, `Deserialize`, and `Verify` are at `+0x4596c0`,
`+0x58c520`, and `+0x58cdb0`. It is a KVTree with four uint8 root keys:

```text
0 -> uint8 version = 0
1 -> uint8 global_depth in 1..21
2 -> Entries subtree
3 -> uint64 generation
```

The Entries subtree has exactly `2 ** global_depth` children. Each child key
is its uint32 directory slot and each value is a Binary[16] bucket byte extent.
Repeated extents implement extendible hashing. Local depth equals global depth
minus `log2(number_of_directory_references)`; verification requires that
reference count to be a power of two.

## Bucket KVTree and file records

`Bucket::Serialize` is at `+0x441754`; `Bucket::Deserialize` is at `+0x57d1a4`.
Its KVTree uses uint8 root keys:

- key 0: required uint8 version 0;
- key 1: optional ordinary-name groups;
- key 2: optional compact Syzygy-name groups.

Both group trees are first keyed by the low uint32 of
`SpookyHash::Hash128(UTF-16LE(filename), seed0=0, seed1=0)`
(`HashFileName`, `+0x57db88`). Ordinary inner keys are wstrings. Compact keys
are 17 bytes: a 16-byte identifier plus kind 0, 1, or 2.

Every inner value is the following complete Terse-v2 stream, emitted by
`serialize_bucket_file_record` at `+0x57dd28`:

```text
bool    tombstone
ULEB32  file_attributes
ULEB64  logical_file_size
SLEB64  creation_FILETIME - bucket_timestamp_base       # ZigZag + ULEB
SLEB64  last_access_FILETIME - bucket_timestamp_base
SLEB64  last_write_FILETIME - bucket_timestamp_base
ULEB32  extent_count
repeat extent_count times:
    ULEB64 byte_offset
    ULEB64 byte_length
```

The ordinary and compact group readers are at `+0x57c9ac` and `+0x57c9d8`.
Tombstoned entries remain serialized but `FindFile`/`ForEachFile` omit them.

Compact names use suffixes kind 0 `.P`, kind 1 `.R`, and kind 2 `.UR`.
`ToSyzygyFileName`/`TryParseSyzygyFileName` are at `+0x5a3334`/`+0x5a33f4`.
The 16 identifier bytes become exactly 32 characters using alphabet
`ABCDEFGHIJKLMNOPQRSTUVWXYZ234567`. Each byte is encoded independently as its
low five bits followed by its high three bits, and the whole string is then
reversed. Captured names confirm the reversal; see
`physical-storage.md`. This is not ordinary bit-packed Base32. It differs from
the DRG in-memory `e_`/`u_`/`s_` Base32hex logical names; loose blob files are
named `e_` + this text.

## Implementation

`src/cacheweave/formats/arx_codec.py` decodes and validates:

- block runs, leaf pointers, and length-prefixed pointer blocks;
- superblocks and HashDirectories;
- Bucket KVTrees, Terse file records, and compact Syzygy names;
- monolithic FileIndex LZ4 streams;
- NextGenAllocator LZ4 streams.

The physical filename and namespace grammar is
`<settings-root>\\0\\<generation>\\<32-character ID>\\0.ARX`; see
`physical-storage.md`. The live validation below identifies the selected
roots, owning namespace, provider, and mapping from DRG objects to Arx file names.
Protected-stream framing and vault serialization are recovered
in `protected-storage.md`. Provider-backed HMAC verification and decryption ran
on the live volume with the session from the image's DPAPI keys (below).

## Live validation

**How the sample was made.** Storage configuration 0x40d, `ArxEnabled`, is a feature gate
(`GetFromFeatureGateBoolean` in `mso20win32client.dll`), not a registry value.
- `Mso::Experiment::GetFullFeatureName` builds the gate name as `Microsoft.Office.` + team + `.` + name, and
  the Storage gates use team 0x1b, `FileIO`. So the gate is `Microsoft.Office.FileIO.ArxEnabled`.
- `Mso::RegistryStores` reads local overrides from ORAPI keys in the same DLL. One of them is
  `HKCU\Software\Microsoft\Office\16.0\Common\ExperimentConfigs\ExternalFeatureOverrides`.
- The lab wrote the gate as `"true"` into that key, its `word` subkey, and
  `...\Common\ExperimentEcs\Overrides` before Word started. Which of the three
  stores Word honoured was not separated.
- Word then kept the fresh test document in `OfficeFileCache\0\0\<namespace>\0.ARX`: 262,144 bytes, next to
  the namespace's `.C4`. The override worked, and this build wrote `0.ARX`
  when the gate was on. No other namespace changed format.

**What the volume holds.**

| blocks (4 KiB) | content |
|---|---|
| 0, 1 | Superblock ZigZag halves (`0x69` + LZ4 KVTree), generations 0 and 1 (key 1) |
| 2, 8 | next-gen allocator states, generations 4 and 5 (bare `Storage::Compression` LZ4) |
| 16, 17 | extendible FileIndex HashDirectory ZigZag halves, generations 4 and 5 |
| 27/28, 30/37 | Bucket KVTrees, two generations each |
| 29 | a pile (`0x96 0x69`) |
| 18–26, 31–36 | protected-stream data |

- The file index lists 73 live files: 70 `e_*.R` and 3 `*.P`. That is the same set as a loose-file namespace
  of a document in the same state, which has 70 `.R`, 3 `.P`, and the `.C4`. The `.C4`, with the vault and
  DocumentMetadata, stays outside the volume.
- `reserved_block_count` is 16, and the allocator's `minimum_allocatable_offset` is 0x10000.

The live volume establishes two layout rules:

1. **A KVTree value tag is one raw byte.** Inline Binary tags reach 0xb5. The Superblock's
   extents are tagged 0x80 and followed at once by their 16 bytes. Piles use the same decoder.
2. **A ZigZag allocator is read at a fixed extent, not at `allocator_root_block`.** The live
   Superblock holds (2, 1) there, which is no byte extent. The two allocator states start at blocks 2 and 8.
   - `Arx::LogicalVolume::LoadAllocations` (`mso20win32client.dll` +0x5986dc, decompiled with the public PDB)
     uses the constant `xmmword_180802CB0` = (0x2000, 0xC000) when the allocator is a `ZigZag`. That is two
     0x6000-byte halves at 0x2000 and 0x8000. Only other allocators read the Superblock's value.
   - A root length of 0 or not 4 KiB-aligned fails the mount with "Allocator root extent is not readable in
     this format; failing mount to force a reseed".
   - `decode_physical_volume` now tries the Superblock's extent, then this fixed one
     (`ZIGZAG_ALLOCATOR_ROOT`), and only then scans the reserved blocks (`scan_reserved_allocator_halves`).
     The file index root agrees with the Superblock's `file_index_root_block` (0x10000, 0x2000).
   - Bucket times are deltas. They fit the Superblock's `creation_time` as their base.

**Recovery.**
- `arx_codec.extract_volume_files` reads every live file through its extents.
- `odc_recover.inventory_namespace` lists those files as if they lay loose in the namespace folder, under the
  paths `0.ARX/<name>`, and reports the chain under `arx_volume`.
- With that, B2, B3, and CW all selected the saved state of the ARX-stored document. Its text equals Word's
  view of the save.
- This is format support. The document was not damaged, so it shows no gain of CW over B3.
- **Carving (C2).** `src/cacheweave/odc_carve.py` now finds volumes by their Superblock pair at cluster boundaries. It reads
  the size from the allocator at the fixed ZigZag root and opens the file index (`carve_arx_volumes`). The
  volume's files go to the carved vault namespace that holds most of their crypt sessions. Names that are not
  plain file names are refused.
  - In a reconstruction fixture, the live volume and its `.C4` were placed at cluster boundaries in 4 MB of noise. The footer carve
    already rebuilt the volume's contiguous protected streams at unaligned offsets (71 streams, 68 of them
    "block"-aligned). The volume carve added the 3 piles. B3 and CW then selected the saved state exactly,
    and B2 was undetermined.
  - **Damaged ARX document (one run).** The carve found the volume by its
    Superblock pair and opened its index: 73 files. 14 of them were new to the footer carve, among them the
    3 piles. But the document could not be rebuilt:
    - The `0.ARX` file lay in two fragments on disk: blocks 0–31 at LCN 5,746,378 and blocks 32–63 at
      LCN 221,324. The two extents are consistent with the volume growing from
      128 to 256 KiB.
    - After the delete, the first fragment was intact (32 of 32 clusters), and the second was entirely
      overwritten (0 of 32). Its files are gone, not merely unread.
    - B2, B3, and CW were undetermined: the evidence names a revision that cannot be rebuilt. No wrong
      state was selected. CW salvaged 18 verified parts, none of them of the named revision.
    - The volume carve reads a volume as one span. For a fragmented volume, the files beyond the first
      fragment come out wrong and fail authentication. Here that made no difference, because their data was
      overwritten anyway.
- **A file gone from the volume's index is still carved by its footer.**
  The volume's index named one file; the other file's
  protected stream stayed in the data blocks, packed at a 16-byte offset. The volume carve listed only the named
  file, and the footer carve found the other one and verified it with the session key (alignment `block`). In
  the live R3 on ARX, 57 of the 108 carved streams sat at such offsets inside the volume.
- **Deleted index records in a live volume.**
  - A fresh ARX document received seven saves after open, a
    2 MB picture added and taken out again, and text appended. The volume grew to 3,416,064 bytes and
    indexes 105 live files.
  - The current index has no record marked deleted. The two HashDirectory halves (generations 14 and 15)
    name the same 105 files.
  - The FileIndex writes every Bucket generation to a new block. Earlier copies stay in freed blocks until
    reused. Tried as Buckets, all 834 blocks gave 13 copies: the 4 current and 9 older ones.
  - The older copies name 186 files, 81 of them no longer in the index: 75 protected streams, 3 piles, and 3
    others. Read at their recorded extents and checked with the session from the image's keys, **71 of the
    75 streams authenticate**; 4 fail (their blocks were reused).
  - `arx_codec.stale_bucket_records` / `extract_volume_files(include_stale=True)` now read them, and
    `odc_recover` lists them as `0.ARX/stale/<name>`. `odc_carve` writes them into the carved namespace,
    marked in the volume summary (`stale_files`). Their HMAC decides, as for any carved stream.
  - On this evidence the engine still selects the saved state exactly (the same revision `...,310`, text
    equal to Word's view) and rebuilds the same five revisions. The deleted files were superseded or
    temporary objects.
  - The one-save live volume had no older copies with other names: nothing had
    been deleted in it.
- A fragmented and partly overwritten volume was seen once live. A
  fragmented volume fails the file-index chain, or its streams do not authenticate. It is reported, never
  patched.
