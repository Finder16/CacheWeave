# ODC architecture recovered from Office 16.0.20527.20196

This page maps the Office modules that implement the Document Cache and follows
the cache lifecycle from Word through the local revision graph to OneDrive.
The call paths come from the analyzed Office binaries; physical placement and
state transitions were checked against captured caches.

## Module boundary

```text
WINWORD.EXE (thin launcher)
    |
    v
wwlib.dll (Word document, persister, coauthoring and working-copy integration)
    |
    v
mso.dll (shared Office document/coauthoring policy and UI-facing state)
    |
    +--> mso20win32client.dll (Syzygy/Arx physical storage and Agile crypt session)
    |
    +--> mso30win32client.dll (DocumentRepository/DRG and WOPI/FSSHTTP)
    |
    v
csi.dll (cache lifecycle, CentralTable, revision graph, sync and maintenance)
    |
    +--> CentralTable + DocumentRevisionGraph + BlobHeap
    |
    +--> WOPI / CellStorage / FSSHTTP transport
    v
SharePoint / OneDrive server state
```

This division follows directly from the symbol sets and call/import edges. The executable
itself has only 162 analyzed functions and no ODC evidence function; the actual
implementation is in the DLLs. In particular, `mso20win32client.dll` contains
the `Syzygy::Cipher`, `Vault`, `Integrity`, Arx, `CPasswordKeyEnc`, and
`CCryptoObj` implementations and no `DocumentRepository`; the 44
`DocumentRevisionGraph::DocumentRepository` functions are in
`mso30win32client.dll`, which has no Syzygy/Arx/crypt-session implementation
symbols.

## Cache lifecycle

- `csi.dll+0x25710` `Csi::StartOfficeFileCache2` checks
  `CFileCache::IsDiskFull`, merges caller settings into
  `StartOfficeFileCacheArgs2`, and delegates to
  `CFileCache::StartOfficeFileCache`. The low-disk branch returns a CSI error
  instead of creating the cache.
- `csi.dll+0x299e0` `GetOfficeFileCacheFolderPath` accepts
  configuration overrides and otherwise builds
  `OfficeFileCache` plus an optional numeric suffix below the parent path. It
  creates/sanitizes the path and caches the result in process memory.
- The shutdown sequence is split across
  `BeginShutdownOfficeFileCache2` (`+0x12f7f0`) and
  `EndShutdownOfficeFileCache2` (`+0x132780`).
- `TryDestroyOfficeFileCache` is at `+0x5ac740` and
  `UpdateNextOfficeFileCacheFolderNumber` at `+0x4e5e50`.

The default root used by this Office generation is therefore a numbered cache
namespace, not a single hard-coded file.

## CentralTable and persisted state

`CentralTable::Instance` (`csi.dll+0x34b0`) receives four independent storage
components:

- `Storage::ISettings`;
- `Disco::IFileSystem`;
- `DocumentRevisionGraph::IDocumentRepository`;
- a fault-policy object.

It creates a `CentralTable::Implementation::FileTable` and retains the settings,
file-system, and document-repository interfaces. The logical store names
`CsiCentralTable` and `CsiCentralTableDB` do not correspond to a separate
database file in the captured caches. A file's central-table columns are Terse
resident properties in that document namespace's `.C4` `DocumentMetadata`,
keyed by column hashes. The cache root otherwise contains the numbered storage
folder and, after a fault, `odc.faults`.

The `PropertySpace_CSIMain::priCacheTable*` data objects expose 194 property
definitions. Each 32-byte definition includes a numeric property ID, encoded
type, name pointer, and description pointer.

Key persisted state includes:

| State | Property ID | Meaning from the binary |
|---|---:|---|
| `FPendingUpload` | `0x08003813` | file has pending uploads |
| `FWorkingCopyDirty` | `0x080038b2` | a partition has a dirty working copy |
| `DownloadBranchRid` | `0x1c0038ae` | root-cell revision ID of download branch |
| `UploadBranchRid` | `0x1c0038af` | root-cell revision ID of upload branch |
| `BaseBranchRid` | `0x1c0038b0` | root-cell revision ID of base branch |
| `WorkingBranchRid` | `0x1c0038b1` | root-cell revision ID of working branch |
| `UnresolvedUpload` | `0x1c00390c` | upload revision that may or may not have reached the server |
| `ServerEtagBeforeSync` | `0x1c00385e` | server ETag observed before synchronization |
| `ServerEtagAfterSync` | `0x1c00385d` | server ETag obtained by download |

The recovery model must therefore be a graph of branches and revisions. A file
name or modification time alone cannot select the current document state.

## Working-copy and metadata updates

`WorkingCopyCam::WorkingCopy::UpdateWorkingCopyInfoInCentralTable`
at `csi.dll+0x1ffae0`:

1. rejects closed files and files not opened read/write;
2. obtains or calculates a quick XOR hash for the working-copy stream;
3. opens persisted metadata transactions;
4. writes working-copy information and, when requested, file properties.

`ServerInfo::GetServerInfoAndWriteToCentralTable` at `+0x1fe5b4` skips local
locations, creates an `IMsoUrl`, asynchronously retrieves server information,
and persists the result. Server capability state is therefore part of cache
interpretation rather than optional UI metadata.

Word consumes this layer through working-copy and revision-graph helpers in
`wwlib.dll`, including:

- `UpdateAndWriteCoauthoringContentCollections` at `+0x76984c`;
- `FClientUpdateAndWriteCoauthoringContentCollections` at `+0x769870`;
- `PersisterOCS::FRevertWorkingCopyFromGraph` at `+0x15e4948`;
- multiple `FWorkingCopyDirty` and `FWorkingCopyInConflict` implementations.

## Upload, download, and revision flow

`CServerAccessRequestOnCellStorage::StartSyncUploadInternal` at
`csi.dll+0x35b638` operates on an `IBranchedFile`, two knowledge objects, an
`ICellStorage`, a partition, and revision IDs. Its path:

1. reads the partition branch and root-cell revision ID;
2. acquires the CellStorage service interface;
3. applies upload options, server-lock state, property-set values, and fragment
   sizing;
4. builds knowledge by querying local changes from the upload branch;
5. executes Put Changes;
6. checks whether the base changed before the upload could be scheduled;
7. updates the base/upload knowledge and persisted revision state.

The function explicitly records `CacheTableUnresolvedUpload` for an upload
revision that might have reached the server. That field is a primary recovery
artifact: it represents uncertainty, not a normal completed upload.

**Lifecycle.**

- Set before the request: `StartSyncUploadInternal` puts the upload revision
  into the request's properties as `priCacheTableUnresolvedUpload` before Put
  Changes goes out.
- Cleared on a settled result: the upload completion handler (`+0x3ae770`)
  writes the null revision, "Upload: UnresolvedUpload: clearing after resolved
  upload". It skips this when the error is one of
  `Csi::IsUnresolvedUploadError` (`+0x21dc30`): request cancelled (web service
  or sync), web service time-out, or disconnected.
- A later start clears it for a first upload that had no base copy
  (`+0x66868`, "No base copy, so first upload was interrupted").
- Stored in the namespace's DocumentMetadata under key `0x01CB6A25`. Only
  partition 0 has it: `FilePartition::FGetUnresolvedUpload` (`+0x49d80`)
  returns null for any other partition. The value is a 20-byte Extended GUID.
- `odc_recover` reports it as `document_metadata.unresolved_upload`, and as the
  `unresolved_upload` column in `revision_references`. It never uses it to
  select: Word's view is the working branch either way.
- It was in none of the 185 lab analyses.

**Live observation.** Under the debugger, every upload attempt set the upload
revision at its start, and the completion handler cleared it at its end: 4 of
4 attempts. In nine probe trials, including five interrupted uploads, the key
never reached the disk. In this build the key is transient. The lasting record of an unconfirmed upload
is the branch columns: in all 242 lab document namespaces, either no upload
column and base = working (settled), or upload = working with an older base
(not confirmed). `odc_recover` reports this as `document_metadata.upload_state`.

`HostContentSyncManager::FindAndCloneBatchContainingRepeatableDownloadAndCoauthoringStatusRequests`
at `+0x198d30` shows that repeatable download and coauthor-status operations are
batched and cloned. A snapshot can consequently contain request state that is
valid but not yet executed.

## WOPI, CellStorage, and FSSHTTP

`Csi::Sync::WopiRequestProcessorFactory::GetRequestProcessor` at
`csi.dll+0x3651b0` dispatches distinct processors for these request classes:

- Download and BaseDownload;
- Upload and chunked upload;
- ExclusiveLock and SchemaLock;
- Coauthoring, EditorsTable, and IsOnlyClient;
- Rename;
- GetVersions, GetDocMetaInfo, Label, ServerTime, and WhoAmI paths represented
  in the request-type set.

Partition and protocol capabilities can select WOPI1, WOPI2 chunked content, an
EditorsTable-specific processor, or an explicit not-yet-implemented no-op.

CellStorage XML output is implemented in `csi.dll`; `WriteKnowledge`
(`+0x58c45c`) has six direct call sites in `WriteRequestResponse`
(`+0x4f6fc0`). `WriteDataElementFragment` is at `+0x58bd9c`.

The transport/data-contract layer is concentrated in `mso30win32client.dll`:

- `Cobalt::Fss::SubRequest::Serialize` at `+0x1ca980`;
- `PropertyGetSubRequestData::Serialize` at `+0x1c9160`;
- parsers/attribute handlers for Cell, Coauth, ExclusiveLock, SchemaLock,
  EditorsTable, Label, and GetVersionList subrequests;
- `SubRequestTypeFromString` at `+0x624c9c` and
  `SubRequestTypeToString` at `+0x1cb80c`.

This supports a layered parser design for CacheWeave: recover the local revision
objects first, then interpret protocol payloads using the published FSSHTTP data
model. It does not support treating every local cache object as a complete
network response. The lower DRG/Syzygy object-name and commit path is detailed
in `physical-storage.md`.

## Maintenance and deletion

The `AgeOutCentralTableMaintenanceSubTask` constructor at
`csi.dll+0x488340` reads:

- `AgeOutPolicy`;
- `AgeOutPolicyLocalVersioning`;
- optionally `AgeOutPolicyIncludingFilesPendingUpload`.

`Evaluate` at `+0x4ab4e0` uses last-accessed time and version type, skips a
never-accessed entry after initializing its access time, computes a maximum age,
and returns a removal outcome when the threshold is exceeded. It contains a
separate pending-upload maximum age and a path that removes a sync-backed file
when it is not in conflict. `RunCentralTableMaintenanceTask` at `+0x36fd2c`
constructs the maintenance subtasks and executes the scan.

Deletion is therefore policy- and state-dependent. Surviving cache bytes do not
imply that an entry was logically live, and missing CentralTable linkage does
not prove the content object was never valid.

## Recovery implications

The current evidence supports this order:

```text
physical cache objects
    -> CentralTable rows and typed properties
    -> document/partition identity
    -> base/download/upload/working revision graph
    -> unresolved requests, errors, locks and server ETags
    -> candidate document state(s) with confidence and provenance
```

The recovery model applies these rules:

- keep base, download, upload, and working revisions distinct;
- never silently promote `UnresolvedUpload` to a completed server revision;
- use dirty/pending flags together with their generation-version properties;
- keep protocol partition and document mode in the state key;
- report conflicts and ambiguous heads rather than selecting the newest bytes;
- preserve property IDs and source record offsets in every recovery result.

## Scope

The implementation map, logical property schema, record framing,
object-to-file mapping, checksums, compression, encryption, and the main state
transitions were validated on personal-OneDrive caches from the tested build.
The rebuilt documents were also checked outside the engine against Word's
saved output. SharePoint Online, OneDrive for Business, IRM, and other Office
channels remain outside this validation set.
