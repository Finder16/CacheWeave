# DocumentRevisionGraph physical storage findings

This page documents the storage implementation in `mso30win32client.dll`
16.0.20527.20196 and its correspondence with captured Office caches. Static
structures are tied to live paths, names, and objects where the captures permit it.

## Storage stack

```text
DocumentRepository
    +-- BlobStore::Store
    |       +-- Syzygy::IInstance / INamespace
    |       +-- BlobFile objects
    |       +-- resident properties (document metadata, revisions, audit log)
    +-- MetadataStore::Store (logical document list and metadata)
```

`DocumentRevisionGraph::DocumentRepository::DocumentRepository`
(`+0x5f99a0`) creates both stores. `BlobStore::Store` (`+0x5ea18c`) builds or
accepts a Syzygy instance and owns a pool of namespaces. `MetadataStore::Store`
(`+0x1fc310`) uses the literal logical name `Metadata`, keeps a document-view
map, and registers for storage notifications.

The physical backend is therefore the Office `Syzygy`/Arx datastore
abstraction, not SQLite or ESE. Its superblock, allocator, file indexes,
HashDirectory, buckets, and file records are now statically recovered in
`arx-container.md`. Static analysis also fixes the outer Superblock at byte
extent `{0,0x2000}`, split into the two 4-KiB generation slots.

## Exact namespace and volume path

The complete static placement chain is now recovered. `BlobStore::Store`
gets the configured base directory from `ISettings` string key `2` and builds:

```text
<settings-root>\0\<generation>\<namespace-id>\0.ARX
                |       |             |          |
                |       |             |          +-- Arx physical volume
                |       |             +-- 32-character Storage::ToBase32 ID
                |       +-- highest numeric generation directory
                +-- fixed BlobStore major-version directory
```

The relevant native routines in `mso30win32client.dll` are:

- `Store::EnsureRootFolder` at `+0x373b24`;
- `Store::CreateMajorVersionDirectory` at `+0x38d198`;
- `Store::CreateGenerationDirectory` at `+0x38d6f4`;
- `build_drg_namespace_path` at `+0x373f10` (CacheWeave name).

The major-version name is the literal `0`. Generation enumeration parses
numeric child names, retains the highest candidate, and removes superseded or
invalid generation folders; if no numeric child exists, it creates generation
`0`. The namespace helper appends `Storage::ToBase32` of the exact 16-byte
document/namespace ID.

This `Storage::ToBase32` is deliberately unusual. Each input byte produces two
RFC4648-alphabet characters, the low five bits first and then the remaining
high three bits (padded with `A`). The complete wide string is then reversed
(`__std_reverse_trivially_swappable_2` at the end of `+0x2a9650`). Live names
confirm the reversal: the namespace folder decodes to the document GUID. The text
reads from the last byte to the first, high digit then low digit, and is not
ordinary bit-packed Base32. For example, bytes `00 01 ... 0f` become:

```text
APAOANAMALAKAJAIAHAGAFAEADACABAA
```

In the loose-file layout the same text names piles (`<id>.P`) and blobs
(`e_<id>.R`). For blobs, the 16-byte ID is `SpookyHash128(plaintext, 0, 0)`;
this was verified on 71/71 live blobs. DRG's in-memory logical name for the
same ID is `e_` plus 26-character Base32hex.

`src/cacheweave/formats/arx_codec.py` implements `encode_syzygy_identifier`, its inverse, and
`build_drg_namespace_path` directly from these routines.

The lower `mso20win32client.dll` chain confirms what lies under that directory.
`Syzygy::Namespace::Add` (`+0x0c93a0`) creates the namespace directory and
records the `_arxvol` resident marker when the Arx-backed path is selected.
`Arx::Instance::Mount` (`+0x58ddd0`) passes that directory to
`Arx::LogicalVolume`; its constructor (`+0x59071c`) appends the fixed wide
literal `0.ARX`. `_arxvol` and `_vault` are resident-property marker names,
not physical child filenames; vault/protected-stream state is a separate layer.
Syzygy's existence check does not merely test the directory: it combines the
namespace path with `BootClusterSetFileName`, whose fixed value is `.C4`, and
tests that boot cluster-set sentinel. Thus a current namespace has at least the
Syzygy `.C4` boot artifact and, when `_arxvol` is enabled, the Arx `0.ARX`
physical volume beneath the same 32-character-ID directory.

**Live values.** The initial capture and every lab
evidence copy agree:
`<settings-root>` is the `OfficeFileCache` folder itself, its only child is the
major-version folder `0`, and the generation is `0`. In 595 copied namespace
folders the generation was always `0`. Each namespace folder is
`Storage::ToBase32` of the document GUID; the
repository root namespace holds only the DocumentList. A cached file's central
table columns are stored in its own namespace's `.C4` DocumentMetadata, so the
row and the namespace are the same document. The volume is `0.ARX` only when the
`ArxEnabled` gate is on (`arx-container.md`).

On a `0.ARX` (the live one included), `decode_physical_volume` in
`src/cacheweave/formats/arx_codec.py` walks
the current physical chain without manually supplying offsets: Superblock
generation, next-gen allocator generation, all byte-addressed allocator
pointer tiers and spilled free-run leaves, allocator-pinned FileIndex root,
and either monolithic files or extendible HashDirectory/Bucket files.

## Blob names and identifiers

The forward and inverse routines are both present:

- `GenerateBlobNameFromIdentifierWithBase32` at `+0x37579c`;
- `GenerateBlobIdentifierFromNameWithBase32` at `+0x324ccc`.

A generated committed-object name has exactly this form:

```text
<prefix>_<26 Base32hex characters>
```

The payload is a 16-byte identifier encoded with
`cppcodec::detail::base32_hex`, without `=` padding. Prefix-to-flag mappings are
visible in both routines:

| Prefix | BlobIdentifier flag | Confirmed use |
|---|---:|---|
| `e_` | `0x04` | Built by `CreateExtrinsicBlobIdentifier`; also produced for the hash-finalized committed ID. |
| `u_` | `0x08` | Random temporary ID created by `TryAddUnprotectedTemporaryBlob`. |
| `s_` | `0x10` | Parsed and generated; no writer found in this build (flag table below). `BlobFile::Write` skips SpookyHash updates for this flag. |

An independent boolean input adds flag `0x20` while parsing.
`TryAddUnprotectedTemporaryBlob` produces `0x08 | 0x20` and
`TryAddTemporaryBlob` produces `0x08`, so `0x20` means unprotected (see the
flag table below). The inverse routine also contains a legacy-looking `t` acceptance
branch, but the current generator never emits `t_`, so CacheWeave does not
generate or accept it yet.

The recovered logical-name grammar covers the confirmed `e_`, `u_`, and `s_`
prefixes and their Base32hex identifiers.

**The flags, from the code that sets them in `mso30win32client.dll`:**

| flag | set by | meaning |
|---:|---|---|
| `0x08` | `Namespace::TryAddTemporaryBlob` (`+0x322760`) | temporary (`u_`), before commit |
| `0x28` | `Namespace::TryAddUnprotectedTemporaryBlob` (`+0x5d9790`) | temporary and unprotected |
| `0x04`, `0x24` | `BlobIdentifier::CreateExtrinsicBlobIdentifier` (`+0x53a85c`) | committed (`e_`), the second unprotected |
| `0x08` -> `0x04` | `BlobFile::PrepareForCommit` (`+0x37922c`) | commit: clears 0x08, sets 0x04, keeps 0x20 |
| `0x10` | only the name parser (`GenerateBlobIdentifierFromNameWithBase32`, `s` -> 0x10) | `s_`; `BlobFile::Write` does not hash it |

- **0x20 marks an unprotected blob.** It is the one difference
  between the protected and the unprotected temporary-blob adders, and the
  namespace has matching `TryFindUnprotectedCommittedBlob` and
  `TryRemoveUnprotectedCommittedBlob`. No live blob had it: every file is a
  protected `e_` stream.
- **0x10 (`s_`) is only read in this build.** The
  identifier code is in `mso30win32client.dll` only (no `BlobIdentifier` or blob-name
  routine in `csi.dll`, `mso.dll`, or mso20). Two scans of mso30 found no writer:
  - every store of 0x10, 0x14, 0x18, 0x30, 0x34, or 0x38 into an identifier's flag byte
    in the blob-store code: none;
  - all 46,664 functions (`.pdata`), for an identifier-shaped write: a 16-byte ID
    store and, 0x10 bytes on, a flag value with bit 0x10, given as an immediate or
    through an `or` just before. 246 such stores exist. The DRG ones are
    `std::variant` indices (0x18 at +0x30), snapshot-optimizer options (0x1b), and
    hash-check error codes. None builds a blob identifier.
  So the parser is the only origin of 0x10. A blob with it is not identified by its
  content hash, because `Write` skips SpookyHash for it. No file on disk had it.

**On disk.** The files use `Storage::ToBase32`
(32 characters), not this 26-character Base32hex form. Across the lab's evidence
copies the namespace folders held 30,091 `e_<ToBase32(id)>.R` protected streams,
2,706 `<ToBase32(pileId)>.P` piles, one `.C4` cluster set each, one `0.ARX`
(the gate run), and three temporary files. No `u_` or `s_` file was ever
written to disk on this personal path.

**Temporary files.** `Disco::Durable::FileSystem::CreateTemporaryFileW`
(mso20 `+0x27e250`) names a temporary file with
`GetTempFileNameW(<target folder>, L"DSC", <random nonzero>)`. So the name is
`DSC` + up to four hex digits + `.tmp`, and the file is created in the target
folder itself. If the name exists already, it draws again. Three such files were
left in namespace folders by two light-damage runs:
Word was ended by the fault while writing. One was 1,205 bytes of
ciphertext-like data and two were empty. A carve or inventory should therefore
treat `DSC*.tmp` in a namespace folder as an uncommitted write. It has no blob ID
yet.

## Write and commit behavior

`BlobStore::BlobFile::Add` (`+0x375ac0`) creates a temporary Syzygy write
stream. `BlobFile::Write` (`+0x321d10`) forwards bytes to that stream and, when
hashing is enabled, feeds them to `SpookyHash::Update`.

`BlobFile::PrepareForCommit` (`+0x37922c`) finalizes a 128-bit SpookyHash into
the 16-byte portion of a new `BlobIdentifier`, sets a committed-state flag, and
reinitializes the hasher. `BlobFile::Commit` (`+0x3792b8`) then moves/renames
the temporary object through the Syzygy namespace to the generated Base32hex
name. The code has separate namespace-interface branches selected by a flag,
and reports temporary-name collisions distinctly.

Consequences:

- committed filenames can be reversed to their 16-byte identifiers without a
  lookup table;
- content hashing and object naming are coupled for newly written blobs;
- temporary objects and committed objects must be inventoried separately;
- a hash-derived filename alone does not reveal the owning document or graph;
  resident metadata and namespace identity are still required.

## Integrity, compression, and protected streams

The binary exposes DRG part metadata keys `Crc32` and `CompressionMethod`, plus
resident properties named `DocumentMetadata`, `DocumentStorageRevisions`, and
`AuditLog`. Their inner payload boundary is now substantially recovered:

- `DocumentMetadata` is a version-2 `Storage::Terse` stream;
- current `DocumentStorageRevisions` is a `0x69`-prefixed LZ4 Frame containing
  a typed `Storage::KeyValueTree`; the reader falls back to legacy Terse;
- `AuditLog` is a Terse-v2 stream containing version and ring cursor followed
  by exactly 4096 fixed-field trace records.

The Terse v2 envelope is `version:u8`, `checksum:u32le`,
`payload_size:u32le`, and payload. Its checksum is the nonstandard MSB-first
`Storage::Crc32` polynomial `0x000000af`, initial 0, no final XOR. KVTree uses
ULEB128, ZigZag signed integers, compact empty/zero tags, and a `+0x46` subtree
tag family. The exact field tables and tested parsers are in
`resident-properties.md`, `src/cacheweave/formats/terse_codec.py`, and
`src/cacheweave/formats/decode_kvtree.py`.

The lower Arx container has verified error paths for malformed allocator block
runs, root-pointer lists, LZ4 frames, KVTree schemas, bucket records, and
missing or corrupt blobs. It does **not** persist a generic CRC header around
ZigZag halves; CRC values there are calculated for diagnostics and tracing only.

`BlobStore::Namespace::AccessProtectedStreams` (`+0x5c0810`) and
`UpdateProtectedStreamsEncryption` (`+0x6298a0`) accept encryption/decryption
provider collections. CSI additionally exposes CLP encrypted-file hash/size
and `WorkingCopy::IsFileClpEncrypted`. A decoder must therefore treat these as
separate layers:

```text
Arx LZ4/KVTree/Terse validation
    -> DRG resident metadata and blob identifier
    -> optional compression
    -> optional protected-stream encryption
    -> document/package bytes
```

The protected-stream framing is now statically exact. Ciphertext is split into
at most `0xff80` bytes, and every shard has a fixed `0x80`-byte Terse-v2 footer
containing version, session ID, salt, a transformed 16-byte HMAC key, and a
64-byte SHA-512 HMAC. Final plaintext is block-aligned with random inner
padding, and the same padding count appears again as random outer bytes after
the last footer. HMAC covers shard index, salt, and ciphertext and is verified
before decryption. `_vault` stores the ordered provider GUIDs and serialized
crypt sessions; provider encryption runs forward and decryption runs in
reverse. The byte grammar, size equations, RVAs, and limitations are in
`protected-storage.md`.

**Live.** On the personal path the selected provider is
`standard-dpapi-machine`. The initial capture and every lab run unwrapped `_vault`
with offline DPAPI from the system hives (input condition C1). Then they
verified the footer HMACs and decrypted the streams. Rebuilt documents matched
the cloud copies byte for byte, 6 of 6. No recovery code
treats a protected or compressed blob as damaged plaintext.

## Live validation

Captures taken before and after open, edit, synchronization, and close confirmed:

- namespace paths: `OfficeFileCache\0\0\<ToBase32(document GUID)>`;
- temporary naming: `DSC<hex>.tmp`;
- provider and session: `standard-dpapi-machine`;
- committed identifiers: the committed ID equals SpookyHash-128 of the stored
  bytes. All 1,651 pile hashes in 23 captured piles name an existing `e_` file,
  and the structural scan re-derives each blob ID from its content.
